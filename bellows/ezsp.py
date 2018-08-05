import asyncio
import binascii
import functools
import logging
import os

from zigpy.exceptions import DeliveryError
import zigpy.application
import zigpy.device
import zigpy.util
import zigpy.zdo

import bellows.types as t
import bellows.zigbee.util
import bellows.uart as uart
from bellows.commands import COMMANDS

LOGGER = logging.getLogger(__name__)

class EZSP:
    direct = t.EmberOutgoingMessageType.OUTGOING_DIRECT
    COMMANDS = COMMANDS
    ezsp_version = 4

    def __init__(self):
        self._pending = {}
        self._multicast_table = {}
        self._callbacks = {}
        self._seq = 0
        self._gw = None
        self._awaiting = {}
        self.COMMANDS_BY_ID = {}
        for name, details in self.COMMANDS.items():
            self.COMMANDS_BY_ID[details[0]] = (name, details[1], details[2])

    async def connect(self, device, baudrate):
        assert self._gw is None
        self._gw = await uart.connect(device, baudrate, self)

    def reset(self):
        return self._gw.reset()

    async def version(self):
        version = self.ezsp_version
        result = await self._command('version', version)
        if result[0] != version:
            LOGGER.debug("Switching to eszp version %d", result[0])
            await self._command('version', result[0])

    def close(self):
        return self._gw.close()

    def _ezsp_frame(self, name, *args):
        c = self.COMMANDS[name]
        data = t.serialize(args, c[1])
        frame = [
            self._seq & 0xff,
            0,    # Frame control. TODO.
            c[0]  # Frame ID
        ]
        if self.ezsp_version >= 5:
            frame.insert(1, 0xFF)  # Legacy Frame ID
            frame.insert(1, 0x00)  # Ext frame control. TODO.

        return bytes(frame) + data

    def _command(self, name, *args):
        LOGGER.debug("Send command %s", name)
        data = self._ezsp_frame(name, *args)
        self._gw.data(data)
        c = self.COMMANDS[name]
        future = asyncio.Future()
        self._awaiting[self._seq] = (c[0], c[2], future)
        self._seq = (self._seq + 1) % 256
        return future

    async def _list_command(self, name, item_frames, completion_frame, spos, *args):
        """Run a command, returning result callbacks as a list"""
        fut = asyncio.Future()
        results = []

        def cb(frame_name, response):
            if frame_name in item_frames:
                results.append(response)
            elif frame_name == completion_frame:
                fut.set_result(response)

        cbid = self.add_callback(cb)
        try:
            v = await self._command(name, *args)
            if v[0] != t.EmberStatus.SUCCESS:
                raise Exception(v)
            v = await fut
            if v[spos] != t.EmberStatus.SUCCESS:
                raise Exception(v)
        finally:
            self.remove_callback(cbid)

        return results

    startScan = functools.partialmethod(
        _list_command,
        'startScan',
        ['energyScanResultHandler', 'networkFoundHandler'],
        'scanCompleteHandler',
        1,
    )
    pollForData = functools.partialmethod(
        _list_command,
        'pollForData',
        ['pollHandler'],
        'pollCompleteHandler',
        0,
    )
    zllStartScan = functools.partialmethod(
        _list_command,
        'zllStartScan',
        ['zllNetworkFoundHandler'],
        'zllScanCompleteHandler',
        0,
    )
    rf4ceDiscovery = functools.partialmethod(
        _list_command,
        'rf4ceDiscovery',
        ['rf4ceDiscoveryResponseHandler'],
        'rf4ceDiscoveryCompleteHandler',
        0,
    )

    async def formNetwork(self, parameters):  # noqa: N802
        fut = asyncio.Future()

        def cb(frame_name, response):
            nonlocal fut
            if frame_name == 'stackStatusHandler':
                fut.set_result(response)

        self.add_callback(cb)
        v = await self._command('formNetwork', parameters)
        if v[0] != t.EmberStatus.SUCCESS:
            raise Exception("Failure forming network: %s" % (v, ))

        v = await fut
        if v[0] != t.EmberStatus.NETWORK_UP:
            raise Exception("Failure forming network: %s" % (v, ))

        return v

    def __getattr__(self, name):
        if name not in self.COMMANDS:
            raise AttributeError("%s not found in COMMANDS" % (name, ))

        return functools.partial(self._command, name)

    def frame_received(self, data):
        """Handle a received EZSP frame

        The protocol has taken care of UART specific framing etc, so we should
        just have EZSP application stuff here, with all escaping/stuffing and
        data randomization removed.
        """
        sequence, frame_id, data = data[0], data[2], data[3:]
        if frame_id == 0xFF:
            frame_id = 0
            if len(data) > 1:
                frame_id = data[1]
                data = data[2:]

        frame_name = self.COMMANDS_BY_ID[frame_id][0]
        LOGGER.debug(
            "Application frame %s (%s) received",
            frame_id,
            frame_name,
        )

        if sequence in self._awaiting:
            expected_id, schema, future = self._awaiting.pop(sequence)
            assert expected_id == frame_id, "Expected frame %s got frame %s" % (expected_id, frame_id)
            result, data = t.deserialize(data, schema)
            future.set_result(result)
        else:
            schema = self.COMMANDS_BY_ID[frame_id][2]
            frame_name = self.COMMANDS_BY_ID[frame_id][0]
            result, data = t.deserialize(data, schema)
            self.handle_callback(frame_name, result)

        if frame_id == 0x00:
            self.ezsp_version = result[0]

    def add_callback(self, cb):
        id_ = hash(cb)
        while id_ in self._callbacks:
            id_ += 1
        self._callbacks[id_] = cb
        return id_

    def remove_callback(self, id_):
        return self._callbacks.pop(id_)

    def handle_callback(self, *args):
        for callback_id, handler in self._callbacks.items():
            try:
                handler(*args)
            except Exception as e:
                LOGGER.exception("Exception running handler", exc_info=e)

    async def initialize(self):
        """Perform basic NCP initialization steps"""

        await self.reset()
        await self.version()

        c = t.EzspConfigId
        await self._cfg(c.CONFIG_STACK_PROFILE, 2)
        await self._cfg(c.CONFIG_SECURITY_LEVEL, 5)
        await self._cfg(c.CONFIG_SUPPORTED_NETWORKS, 1)
        zdo = (
            t.EmberZdoConfigurationFlags.APP_RECEIVES_SUPPORTED_ZDO_REQUESTS |
            t.EmberZdoConfigurationFlags.APP_HANDLES_UNSUPPORTED_ZDO_REQUESTS
        )
        await self._cfg(c.CONFIG_APPLICATION_ZDO_FLAGS, zdo)
        await self._cfg(c.CONFIG_TRUST_CENTER_ADDRESS_CACHE_SIZE, 2)
        await self._cfg(c.CONFIG_ADDRESS_TABLE_SIZE, 16)
        await self._cfg(c.CONFIG_SOURCE_ROUTE_TABLE_SIZE, 8)
        await self._cfg(c.CONFIG_MAX_END_DEVICE_CHILDREN, 32)
        await self._cfg(c.CONFIG_KEY_TABLE_SIZE, 1)
        await self._cfg(c.CONFIG_TRANSIENT_KEY_TIMEOUT_S, 180, True)
        await self._cfg(c.CONFIG_END_DEVICE_POLL_TIMEOUT, 60)
        await self._cfg(c.CONFIG_END_DEVICE_POLL_TIMEOUT_SHIFT, 6)
        await self._cfg(c.CONFIG_APS_UNICAST_MESSAGE_COUNT, 20)
        await self._cfg(c.CONFIG_PACKET_BUFFER_COUNT, 0xff)

    async def startup(self, auto_form=False):
        """Perform a complete application startup"""
        LOGGER.debug("gtak initialize")
        await self.initialize()

        LOGGER.debug("gtak network init start")
        v = await self.networkInit()
        LOGGER.debug("gtak network init finish")
        if v[0] != t.EmberStatus.SUCCESS:
            if not auto_form:
                raise Exception("Could not initialize network")
            await self.form_network()

        LOGGER.debug("gtak network params")
        v = await self.getNetworkParameters()
        assert v[0] == t.EmberStatus.SUCCESS  # TODO: Better check
        if v[1] != t.EmberNodeType.COORDINATOR:
            if not auto_form:
                raise Exception("Network not configured as coordinator")

            LOGGER.info("Forming network")
            await self.leaveNetwork()
            await asyncio.sleep(1)  # TODO
            await self.form_network()

        await self._policy()
        nwk = await self.getNodeId()
        self._nwk = nwk[0]
        ieee = await self.getEui64()
        self._ieee = ieee[0]

        self.add_callback(self.ezsp_callback_handler)

        await self._read_multicast_table()
        LOGGER.debug("gtak Finished setup")

    async def form_network(self, channel=15, pan_id=None, extended_pan_id=None):
        channel = t.uint8_t(channel)

        if pan_id is None:
            pan_id = t.uint16_t.from_bytes(os.urandom(2), 'little')
        pan_id = t.uint16_t(pan_id)

        if extended_pan_id is None:
            extended_pan_id = t.fixed_list(8, t.uint8_t)([t.uint8_t(0)] * 8)

        initial_security_state = bellows.zigbee.util.zha_security(controller=True)
        v = await self.setInitialSecurityState(initial_security_state)
        assert v[0] == t.EmberStatus.SUCCESS  # TODO: Better check

        parameters = t.EmberNetworkParameters()
        parameters.panId = pan_id
        parameters.extendedPanId = extended_pan_id
        parameters.radioTxPower = t.uint8_t(8)
        parameters.radioChannel = channel
        parameters.joinMethod = t.EmberJoinMethod.USE_MAC_ASSOCIATION
        parameters.nwkManagerId = t.EmberNodeId(0)
        parameters.nwkUpdateId = t.uint8_t(0)
        parameters.channels = t.uint32_t(0)

        await self.formNetwork(parameters)
        await self.setValue(t.EzspValueId.VALUE_STACK_TOKEN_WRITING, 1)

    async def _cfg(self, config_id, value, optional=False):
        v = await self.setConfigurationValue(config_id, value)
        if not optional:
            assert v[0] == t.EmberStatus.SUCCESS  # TODO: Better check

    async def _policy(self):
        """Set up the policies for what the NCP should do"""
        
        v = await self.setPolicy(
            t.EzspPolicyId.TC_KEY_REQUEST_POLICY,
            t.EzspDecisionId.DENY_TC_KEY_REQUESTS,
        )
        assert v[0] == t.EmberStatus.SUCCESS  # TODO: Better check
        v = await self.setPolicy(
            t.EzspPolicyId.APP_KEY_REQUEST_POLICY,
            t.EzspDecisionId.ALLOW_APP_KEY_REQUESTS,
        )
        assert v[0] == t.EmberStatus.SUCCESS  # TODO: Better check
        v = await self.setPolicy(
            t.EzspPolicyId.TRUST_CENTER_POLICY,
            t.EzspDecisionId.ALLOW_PRECONFIGURED_KEY_JOINS,
        )
        assert v[0] == t.EmberStatus.SUCCESS  # TODO: Better check

    async def force_remove(self, dev):
        # This should probably be delivered to the parent device instead
        # of the device itself.
        await self.removeDevice(dev.nwk, dev.ieee, dev.ieee)

    def ezsp_callback_handler(self, frame_name, args):
        if frame_name == 'incomingMessageHandler':
            self._handle_frame(*args)
        elif frame_name == 'messageSentHandler':
            if args[4] != t.EmberStatus.SUCCESS:
                self._handle_frame_failure(*args)
            else:
                self._handle_frame_sent(*args)
        elif frame_name == 'trustCenterJoinHandler':
            if args[2] == t.EmberDeviceUpdate.DEVICE_LEFT:
                self.handle_leave(args[0], args[1])
            else:
                self.handle_join(args[0], args[1], args[4])

    def _handle_frame(self, message_type, aps_frame, lqi, rssi, sender, binding_index, address_index, message):
        try:
            device = self.get_device(nwk=sender)
        except KeyError:
            LOGGER.debug("No such device %s", sender)
            return

        device.radio_details(lqi, rssi)
        try:
            tsn, command_id, is_reply, args = self.deserialize(device, aps_frame.sourceEndpoint, aps_frame.clusterId, message)
        except ValueError as e:
            LOGGER.error("Failed to parse message (%s) on cluster %d, because %s", binascii.hexlify(message), aps_frame.clusterId, e)
            return

        if is_reply:
            self._handle_reply(device, aps_frame, tsn, command_id, args)
        else:
            self.handle_message(device, False, aps_frame.profileId, aps_frame.clusterId, aps_frame.sourceEndpoint, aps_frame.destinationEndpoint, tsn, command_id, args)

    def _handle_reply(self, sender, aps_frame, tsn, command_id, args):
        try:
            send_fut, reply_fut = self._pending[tsn]
            if send_fut.done():
                self._pending.pop(tsn)
            if reply_fut:
                reply_fut.set_result(args)
            return
        except KeyError:
            LOGGER.warning("Unexpected response TSN=%s command=%s args=%s", tsn, command_id, args)
        except asyncio.futures.InvalidStateError as exc:
            LOGGER.debug("Invalid state on future - probably duplicate response: %s", exc)
            # We've already handled, don't drop through to device handler
            return

        self.handle_message(sender, True, aps_frame.profileId, aps_frame.clusterId, aps_frame.sourceEndpoint, aps_frame.destinationEndpoint, tsn, command_id, args)

    def _handle_frame_failure(self, message_type, destination, aps_frame, message_tag, status, message):
        try:
            send_fut, reply_fut = self._pending.pop(message_tag)
            send_fut.set_exception(DeliveryError("Message send failure _frame_failure: %s" % (status, )))
            if reply_fut:
                reply_fut.cancel()
        except KeyError:
            LOGGER.warning("Unexpected message send failure _frame_failure")
        except asyncio.futures.InvalidStateError as exc:
            LOGGER.debug("Invalid state on future - probably duplicate response: %s", exc)

    def _handle_frame_sent(self, message_type, destination, aps_frame, message_tag, status, message):
        try:
            send_fut, reply_fut = self._pending[message_tag]
            # Sometimes messageSendResult and a reply come out of order
            # If we've already handled the reply, delete pending
            if reply_fut is None or reply_fut.done():
                self._pending.pop(message_tag)
            send_fut.set_result(True)
        except KeyError:
            LOGGER.warning("Unexpected message send notification")
        except asyncio.futures.InvalidStateError as exc:
            LOGGER.debug("Invalid state on future - probably duplicate response: %s", exc)

    @zigpy.util.retryable_request
    async def request(self, nwk, profile, cluster, src_ep, dst_ep, sequence, data, expect_reply=True, timeout=10):
        assert sequence not in self._pending
        send_fut = asyncio.Future()
        reply_fut = None
        if expect_reply:
            reply_fut = asyncio.Future()
        self._pending[sequence] = (send_fut, reply_fut)

        aps_frame = t.EmberApsFrame()
        aps_frame.profileId = t.uint16_t(profile)
        aps_frame.clusterId = t.uint16_t(cluster)
        aps_frame.sourceEndpoint = t.uint8_t(src_ep)
        aps_frame.destinationEndpoint = t.uint8_t(dst_ep)
        aps_frame.options = t.EmberApsOption(
            t.EmberApsOption.APS_OPTION_RETRY |
            t.EmberApsOption.APS_OPTION_ENABLE_ROUTE_DISCOVERY
        )
        aps_frame.groupId = t.uint16_t(0)
        aps_frame.sequence = t.uint8_t(sequence)

        v = await self.sendUnicast(self.direct, nwk, aps_frame, sequence, data)
        if v[0] != t.EmberStatus.SUCCESS:
            self._pending.pop(sequence)
            send_fut.cancel()
            if expect_reply:
                reply_fut.cancel()
            raise DeliveryError("Message send failure _send_unicast_fail %s" % (v[0], ))
        try:
            v = await send_fut
        except DeliveryError as e:
            LOGGER.debug("DeliveryError: %s", e)
            raise
        except Exception as e:
            LOGGER.debug("other Exception: %s", e)
        if expect_reply:
            v = await asyncio.wait_for(reply_fut, timeout)
        return v

    async def permit(self, time_s=60):
        assert 0 <= time_s <= 254
        """ send mgmt-permit-join to all router """
        await self.send_zdo_broadcast(0x0036, 0x0000, 0x00, [time_s, 0])
        return self.permitJoining(time_s)

    async def permit_with_key(self, node, code, time_s=60):
        if type(node) is not t.EmberEUI64:
            node = t.EmberEUI64([t.uint8_t(p) for p in node])

        key = zigpy.util.convert_install_code(code)
        if key is None:
            raise Exception("Invalid install code")

        v = await self.addTransientLinkKey(node, key)
        if v[0] != t.EmberStatus.SUCCESS:
            raise Exception("Failed to set link key")

        v = await self.setPolicy(
            t.EzspPolicyId.TC_KEY_REQUEST_POLICY,
            t.EzspDecisionId.GENERATE_NEW_TC_LINK_KEY,
        )
        if v[0] != t.EmberStatus.SUCCESS:
            raise Exception("Failed to change policy to allow generation of new trust center keys")
        """ send mgmt-permit-join to all router """
        await self.send_zdo_broadcast(0x0036, 0x0000, 0x00, [time_s, 0])
        return self.permitJoining(time_s, True)

    async def send_zdo_broadcast(self, command, grpid, radius, args):
        """ create aps_frame for zdo broadcast"""
        aps_frame = t.EmberApsFrame()
        aps_frame.profileId = t.uint16_t(0x0000)        # 0 for zdo
        aps_frame.clusterId = t.uint16_t(command)
        aps_frame.sourceEndpoint = t.uint8_t(0)         # endpoint 0x00 for zdo
        aps_frame.destinationEndpoint = t.uint8_t(0)   # endpoint 0x00 for zdo
        aps_frame.options = t.EmberApsOption(
            t.EmberApsOption.APS_OPTION_NONE
        )
        aps_frame.groupId = t.uint16_t(grpid)
        aps_frame.sequence = t.uint8_t(self.get_sequence())
        radius = t.uint8_t(radius)
        data = aps_frame.sequence.to_bytes(1, 'little')
        schema = zigpy.zdo.types.CLUSTERS[command][2]
        data += t.serialize(args, schema)
        LOGGER.debug("zdo-broadcast: %s - %s", aps_frame, data)
        await self.sendBroadcast(0xfffd, aps_frame, radius, len(data), data)

    async def subscribe_group(self, group_id):
        # check if already subscribed, if not find a free entry and subscribe group_id

        
        index = None
        for entry_id in self._multicast_table.keys():
            if self._multicast_table[entry_id].multicastId == group_id:
                LOGGER.debug("multicast group %s already subscribed", group_id)
                return
            if self._multicast_table[entry_id].endpoint == 0:
                index = entry_id
        if index is None:
            LOGGER.critical("multicast table full,  can not add %s", group_id)
            return
        self._multicast_table[index].endpoint = t.uint8_t(1)
        self._multicast_table[index].multicastId = t.EmberMulticastId(group_id)
        result = await self.setMulticastTableEntry(t.uint8_t(index), self._multicast_table[index])
        return result

    async def unsubscribe_group(self, group_id):
        # check if subscribed and then remove
        
        state = 2
        for entry_id in self._multicast_table.keys():
            if self._multicast_table[entry_id].multicastId == group_id:
                self._multicast_table[entry_id].endpoint = 0
                self._multicast_table[entry_id].multicastId = group_id
                (state, ) = await self.setMulticastTableEntry([entry_id, self._multicast_table[entry_id]])
        return state

    async def _read_multicast_table(self):
        # initialize copy of multicast_table, keep a copy in memory to speed up r/w
        
        entry_id = 0
        while True:
            (state, MulticastTableEntry) = await self.getMulticastTableEntry(entry_id)
            LOGGER.debug("read multicast entry %s status %s: %s", entry_id, state, MulticastTableEntry)
            if state == t.EmberStatus.SUCCESS:
                self._multicast_table[entry_id] = MulticastTableEntry
#                if MulticastTableEntry.endpoint:
#                    self._multicast_table["grp_index"][MulticastTableEntry.multicastId] = entry_id
            else:
                break
            entry_id += 1

    async def _write_multicast_table(self):
        # write copy to NCP
        pass