import asyncio
import binascii
import logging
import os

from zigpy.exceptions import DeliveryError
import zigpy.application
import zigpy.device
import zigpy.util
import zigpy.zdo

import bellows.types as t
import bellows.zigbee.util

LOGGER = logging.getLogger(__name__)

class ControllerApplication(zigpy.application.ControllerApplication):

    def __init__(self, ezsp, database_file=None):
        super().__init__(database_file=database_file)
        self._ezsp = ezsp

    async def startup(self, auto_form=False):
        LOGGER.debug("gtak starting up")
        return self._ezsp.startup(auto_form)

    async def permit(self, time_s=60):
        return self._ezsp.permit(time_s)

    async def subscribe_group(self, group_id):
        return self._ezsp.subscribe_group(group_id)

    async def unsubscribe_group(self, group_id):
        return self._ezsp.unsubscribe_group(group_id)
