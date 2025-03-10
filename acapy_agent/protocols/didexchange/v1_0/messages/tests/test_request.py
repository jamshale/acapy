from unittest import IsolatedAsyncioTestCase, mock

from ......connections.models.diddoc import DIDDoc, PublicKey, PublicKeyType, Service
from ......messaging.decorators.attach_decorator import AttachDecorator
from ......utils.testing import create_test_profile
from ......wallet.base import BaseWallet
from ......wallet.did_method import SOV, DIDMethods
from ......wallet.key_type import ED25519
from .....didcomm_prefix import DIDCommPrefix
from ...message_types import DIDX_REQUEST
from ..request import DIDXRequest


class TestConfig:
    test_seed = "testseed000000000000000000000001"
    test_did = "55GkHamhTU1ZbTbV2ab9DE"
    test_verkey = "3Dn1SJNPaCXcvvJvSbsFWP2xaCjMom3can8CQNhWrTRx"
    test_label = "Label"
    test_endpoint = "http://localhost"
    goal_code = "pytest"
    goal = "pass pytest"

    def make_did_doc(self):
        doc = DIDDoc(did=self.test_did)
        controller = self.test_did
        ident = "1"
        pk_value = self.test_verkey
        pk = PublicKey(
            self.test_did,
            ident,
            pk_value,
            PublicKeyType.ED25519_SIG_2018,
            controller,
            False,
        )
        doc.set(pk)
        recip_keys = [pk]
        router_keys = []
        service = Service(
            self.test_did,
            "indy",
            "IndyAgent",
            recip_keys,
            router_keys,
            self.test_endpoint,
        )
        doc.set(service)
        return doc


class TestDIDXRequest(IsolatedAsyncioTestCase, TestConfig):
    async def asyncSetUp(self):
        self.profile = await create_test_profile()
        self.profile.context.injector.bind_instance(DIDMethods, DIDMethods())
        async with self.profile.session() as session:
            wallet = session.inject(BaseWallet)
            self.did_info = await wallet.create_local_did(
                method=SOV,
                key_type=ED25519,
            )

            did_doc_attach = AttachDecorator.data_base64(self.make_did_doc().serialize())
            await did_doc_attach.data.sign(self.did_info.verkey, wallet)

        self.request = DIDXRequest(
            label=TestConfig.test_label,
            did=TestConfig.test_did,
            did_doc_attach=did_doc_attach,
            goal_code=TestConfig.goal_code,
            goal=TestConfig.goal,
        )

    def test_init(self):
        """Test initialization."""
        assert self.request.label == TestConfig.test_label
        assert self.request.did == TestConfig.test_did
        assert self.request.goal_code == TestConfig.goal_code
        assert self.request.goal == TestConfig.goal

    def test_type(self):
        """Test type."""
        assert self.request._type == DIDCommPrefix.qualify_current(DIDX_REQUEST)

    @mock.patch(
        "acapy_agent.protocols.didexchange.v1_0.messages.request.DIDXRequestSchema.load"
    )
    def test_deserialize(self, mock_request_schema_load):
        """
        Test deserialization.
        """
        obj = {"obj": "obj"}

        request = DIDXRequest.deserialize(obj)
        mock_request_schema_load.assert_called_once_with(obj)

        assert request is mock_request_schema_load.return_value

    @mock.patch(
        "acapy_agent.protocols.didexchange.v1_0.messages.request.DIDXRequestSchema.dump"
    )
    def test_serialize(self, mock_request_schema_dump):
        """
        Test serialization.
        """
        request_dict = self.request.serialize()
        mock_request_schema_dump.assert_called_once_with(self.request)

        assert request_dict is mock_request_schema_dump.return_value

    def test_method_other_than_indy(self):
        """Test method other than indy."""
        request = DIDXRequest(
            label=TestConfig.test_label,
            did="did:web:example.com:alice",
            did_doc_attach=None,
            goal_code=TestConfig.goal_code,
            goal=TestConfig.goal,
        )
        request_dict = request.serialize()
        new_request = DIDXRequest.deserialize(request_dict)
        assert request.serialize() == new_request.serialize()


class TestDIDXRequestSchema(IsolatedAsyncioTestCase, TestConfig):
    """Test request schema."""

    async def asyncSetUp(self):
        self.profile = await create_test_profile()
        self.profile.context.injector.bind_instance(DIDMethods, DIDMethods())
        async with self.profile.session() as session:
            wallet = session.inject(BaseWallet)
            self.did_info = await wallet.create_local_did(
                method=SOV,
                key_type=ED25519,
            )

            did_doc_attach = AttachDecorator.data_base64(self.make_did_doc().serialize())
            await did_doc_attach.data.sign(self.did_info.verkey, wallet)

        self.request = DIDXRequest(
            label=TestConfig.test_label,
            did=TestConfig.test_did,
            did_doc_attach=did_doc_attach,
            goal_code="pytest",
            goal="pass pytest",
        )

    async def test_make_model(self):
        data = self.request.serialize()
        model_instance = DIDXRequest.deserialize(data)
        assert isinstance(model_instance, DIDXRequest)
