from unittest.async_case import IsolatedAsyncioTestCase

import logging
import pytest
from acapy_agent.utils.testing import create_test_profile
from ..manager import DidCheqdManager
from ....wallet.did_method import DIDMethods
from ....wallet.key_type import KeyTypes
from ....cache.base import BaseCache
from ....cache.in_memory import InMemoryCache


@pytest.mark.anoncreds
class TestCheqdDidManager(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        did_methods = DIDMethods()
        self.profile = await create_test_profile(
            settings={"wallet.type": "askar-anoncreds"},
        )
        self.profile.context.injector.bind_instance(DIDMethods, did_methods)
        self.profile.context.injector.bind_instance(KeyTypes, KeyTypes())
        self.logger = logging.getLogger(__name__)
        self.profile.context.injector.bind_instance(BaseCache, InMemoryCache())

    async def test_create_did(self):
        response = await DidCheqdManager(self.profile).create({})
        did = response.get("did")
        assert did.startswith("did:cheqd:testnet")
        self.logger.info(f"DID: {did}")
        assert response.get("verkey")
