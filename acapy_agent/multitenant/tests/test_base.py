from datetime import datetime, timezone
from unittest import IsolatedAsyncioTestCase

import jwt

from ...config.base import InjectionError
from ...messaging.responder import BaseResponder
from ...protocols.coordinate_mediation.v1_0.manager import (
    MediationManager,
    MediationRecord,
)
from ...protocols.coordinate_mediation.v1_0.route_manager import RouteManager
from ...protocols.routing.v1_0.models.route_record import RouteRecord
from ...storage.askar import AskarStorage
from ...storage.error import StorageNotFoundError
from ...tests import mock
from ...utils.testing import create_test_profile
from ...wallet.base import BaseWallet
from ...wallet.did_info import DIDInfo
from ...wallet.did_method import SOV
from ...wallet.key_type import ED25519
from ...wallet.models.wallet_record import WalletRecord
from .. import base as test_module
from ..base import BaseMultitenantManager
from ..error import MultitenantManagerError, WalletKeyMissingError


class MockMultitenantManager(BaseMultitenantManager):
    async def get_wallet_profile(
        self,
        base_context,
        wallet_record: WalletRecord,
        extra_settings: dict = ...,
        *,
        provision=False,
    ):
        """Do nothing."""

    async def remove_wallet_profile(self, profile):
        """Do nothing."""

    @property
    def open_profiles(self):
        """Do nothing."""


class TestBaseMultitenantManager(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.profile = await create_test_profile(
            {
                "wallet.name": "default",
            }
        )
        self.context = self.profile.context

        self.responder = mock.CoroutineMock(send=mock.CoroutineMock())
        self.profile.context.injector.bind_instance(BaseResponder, self.responder)
        self.manager = MockMultitenantManager(self.profile)

    async def test_init_throws_no_profile(self):
        with self.assertRaises(MultitenantManagerError):
            MockMultitenantManager(None)

    async def test_get_default_mediator(self):
        with mock.patch.object(
            MediationManager, "get_default_mediator"
        ) as get_default_mediator:
            mediation_record = MediationRecord()

            # has default mediator
            get_default_mediator.return_value = mediation_record
            default_mediator = await self.manager.get_default_mediator()
            assert default_mediator is mediation_record

            # Doesn't have default mediator
            get_default_mediator.return_value = None
            default_mediator = await self.manager.get_default_mediator()
            assert default_mediator is None

    async def test_get_webhook_urls_dispatch_type_base(self):
        wallet_record = WalletRecord(
            settings={
                "wallet.dispatch_type": "base",
                "wallet.webhook_urls": ["subwallet-webhook-url"],
            },
        )
        self.context.update_settings({"admin.webhook_urls": ["base-webhook-url"]})
        webhook_urls = self.manager.get_webhook_urls(self.context, wallet_record)
        assert webhook_urls == ["base-webhook-url"]

    async def test_get_webhook_urls_dispatch_type_default(self):
        wallet_record = WalletRecord(
            settings={
                "wallet.dispatch_type": "default",
                "wallet.webhook_urls": ["subwallet-webhook-url"],
            },
        )
        self.context.update_settings({"admin.webhook_urls": ["base-webhook-url"]})
        webhook_urls = self.manager.get_webhook_urls(self.context, wallet_record)
        assert webhook_urls == ["subwallet-webhook-url"]

    async def test_get_webhook_urls_dispatch_type_both(self):
        wallet_record = WalletRecord(
            settings={
                "wallet.dispatch_type": "both",
                "wallet.webhook_urls": ["subwallet-webhook-url"],
            },
        )
        self.context.update_settings({"admin.webhook_urls": ["base-webhook-url"]})
        webhook_urls = self.manager.get_webhook_urls(self.context, wallet_record)
        assert "base-webhook-url" in webhook_urls
        assert "subwallet-webhook-url" in webhook_urls

    async def test_wallet_exists_name_is_root_profile_name(self):
        async with self.profile.session() as session:
            wallet_name_exists = await self.manager._wallet_name_exists(
                session, "default"
            )
            assert wallet_name_exists is True

    async def test_wallet_exists_in_wallet_record(self):
        async with self.profile.session() as session:
            # create wallet record with existing wallet_name
            wallet_record = WalletRecord(
                key_management_mode="managed",
                settings={"wallet.name": "another_test_wallet"},
            )
            await wallet_record.save(session)

            wallet_name_exists = await self.manager._wallet_name_exists(
                session, "another_test_wallet"
            )
            assert wallet_name_exists is True

    async def test_wallet_exists_false(self):
        async with self.profile.session() as session:
            wallet_name_exists = await self.manager._wallet_name_exists(
                session, "another_test_wallet"
            )
            assert wallet_name_exists is False

    async def test_get_wallet_by_key_routing_record_does_not_exist(self):
        recipient_key = "test"

        with mock.patch.object(WalletRecord, "retrieve_by_id") as retrieve_by_id:
            wallet = await self.manager._get_wallet_by_key(recipient_key)

            assert wallet is None
            retrieve_by_id.assert_not_called()

        await self.manager._get_wallet_by_key(recipient_key)

    async def test_get_wallet_by_key_wallet_record_does_not_exist(self):
        recipient_key = "test-recipient-key"
        wallet_id = "test-wallet-id"

        route_record = RouteRecord(wallet_id=wallet_id, recipient_key=recipient_key)
        async with self.profile.session() as session:
            await route_record.save(session)

        with self.assertRaises(StorageNotFoundError):
            await self.manager._get_wallet_by_key(recipient_key)

    async def test_get_wallet_by_key(self):
        recipient_key = "test-recipient-key"

        wallet_record = WalletRecord(settings={})
        async with self.profile.session() as session:
            await wallet_record.save(session)

            route_record = RouteRecord(
                wallet_id=wallet_record.wallet_id, recipient_key=recipient_key
            )
            await route_record.save(session)

        wallet = await self.manager._get_wallet_by_key(recipient_key)

        assert isinstance(wallet, WalletRecord)

    async def test_create_wallet_removes_key_only_unmanaged_mode(self):
        with mock.patch.object(self.manager, "get_wallet_profile") as get_wallet_profile:
            get_wallet_profile.return_value = await create_test_profile()

            unmanaged_wallet_record = await self.manager.create_wallet(
                {"wallet.key": "test_key"}, WalletRecord.MODE_UNMANAGED
            )
            managed_wallet_record = await self.manager.create_wallet(
                {"wallet.key": "test_key"}, WalletRecord.MODE_MANAGED
            )

            assert unmanaged_wallet_record.settings.get("wallet.key") is None
            assert managed_wallet_record.settings.get("wallet.key") == "test_key"

    async def test_create_wallet_fails_if_wallet_name_exists(self):
        with mock.patch.object(
            self.manager, "_wallet_name_exists"
        ) as _wallet_name_exists:
            _wallet_name_exists.return_value = True

            with self.assertRaises(
                MultitenantManagerError,
                msg="Wallet with name test_wallet already exists",
            ):
                await self.manager.create_wallet(
                    {"wallet.name": "test_wallet"}, WalletRecord.MODE_MANAGED
                )

    async def test_create_wallet_saves_wallet_record_creates_profile(self):
        mock_route_manager = mock.MagicMock()
        mock_route_manager.route_verkey = mock.CoroutineMock()
        self.context.injector.bind_instance(RouteManager, mock_route_manager)

        with (
            mock.patch.object(WalletRecord, "save") as wallet_record_save,
            mock.patch.object(self.manager, "get_wallet_profile") as get_wallet_profile,
        ):
            get_wallet_profile.return_value = await create_test_profile()

            wallet_record = await self.manager.create_wallet(
                {"wallet.name": "test_wallet", "wallet.key": "test_key"},
                WalletRecord.MODE_MANAGED,
            )

            wallet_record_save.assert_called_once()
            get_wallet_profile.assert_called_once_with(
                self.profile.context,
                wallet_record,
                {"wallet.key": "test_key"},
                provision=True,
            )
            mock_route_manager.route_verkey.assert_not_called()
            assert isinstance(wallet_record, WalletRecord)
            assert wallet_record.wallet_name == "test_wallet"
            assert wallet_record.key_management_mode == WalletRecord.MODE_MANAGED
            assert wallet_record.wallet_key == "test_key"

    async def test_create_wallet_adds_wallet_route(self):
        did_info = DIDInfo(
            did="public-did",
            verkey="test_verkey",
            metadata={"meta": "data"},
            method=SOV,
            key_type=ED25519,
        )

        mock_route_manager = mock.MagicMock()
        mock_route_manager.route_verkey = mock.CoroutineMock()

        with (
            mock.patch.object(WalletRecord, "save") as wallet_record_save,
            mock.patch.object(self.manager, "get_wallet_profile") as get_wallet_profile,
            mock.patch.object(BaseWallet, "get_public_did") as get_public_did,
        ):
            mock_profile = await create_test_profile()
            mock_profile.context.injector.bind_instance(RouteManager, mock_route_manager)
            get_wallet_profile.return_value = mock_profile
            get_public_did.return_value = did_info

            wallet_record = await self.manager.create_wallet(
                {"wallet.name": "test_wallet", "wallet.key": "test_key"},
                WalletRecord.MODE_MANAGED,
            )

            wallet_record_save.assert_called_once()
            get_wallet_profile.assert_called_once_with(
                self.profile.context,
                wallet_record,
                {"wallet.key": "test_key"},
                provision=True,
            )
            assert isinstance(wallet_record, WalletRecord)
            assert wallet_record.wallet_name == "test_wallet"
            assert wallet_record.key_management_mode == WalletRecord.MODE_MANAGED
            assert wallet_record.wallet_key == "test_key"

    async def test_update_wallet(self):
        with (
            mock.patch.object(WalletRecord, "retrieve_by_id") as retrieve_by_id,
            mock.patch.object(WalletRecord, "save") as wallet_record_save,
        ):
            wallet_id = "test-wallet-id"
            retrieve_by_id.return_value = WalletRecord(
                wallet_id=wallet_id,
                settings={
                    "wallet.webhook_urls": ["test-webhook-url"],
                    "wallet.dispatch_type": "both",
                },
            )

            new_settings = {
                "wallet.webhook_urls": ["new-webhook-url"],
                "wallet.dispatch_type": "default",
            }
            wallet_record = await self.manager.update_wallet(wallet_id, new_settings)

            wallet_record_save.assert_called_once()

            assert isinstance(wallet_record, WalletRecord)
            assert wallet_record.wallet_webhook_urls == ["new-webhook-url"]
            assert wallet_record.wallet_dispatch_type == "default"

    async def test_remove_wallet_fails_no_wallet_key_but_required(self):
        with mock.patch.object(WalletRecord, "retrieve_by_id") as retrieve_by_id:
            retrieve_by_id.return_value = WalletRecord(
                wallet_id="test",
                key_management_mode=WalletRecord.MODE_UNMANAGED,
                settings={"wallet.type": "indy"},
            )

            with self.assertRaises(WalletKeyMissingError):
                await self.manager.remove_wallet("test")

    async def test_remove_wallet_removes_profile_wallet_storage_records(self):
        with (
            mock.patch.object(WalletRecord, "retrieve_by_id") as retrieve_by_id,
            mock.patch.object(self.manager, "get_wallet_profile") as get_wallet_profile,
            mock.patch.object(
                self.manager, "remove_wallet_profile"
            ) as remove_wallet_profile,
            mock.patch.object(WalletRecord, "delete_record") as wallet_delete_record,
            mock.patch.object(AskarStorage, "delete_all_records") as delete_all_records,
        ):
            wallet_record = WalletRecord(
                wallet_id="test",
                key_management_mode=WalletRecord.MODE_UNMANAGED,
                settings={"wallet.type": "indy", "wallet.key": "test_key"},
            )
            wallet_profile = await create_test_profile(
                {"wallet.name": "test", "wallet.key": "test_key"}
            )

            retrieve_by_id.return_value = wallet_record
            get_wallet_profile.return_value = wallet_profile

            await self.manager.remove_wallet("test")

            get_wallet_profile.assert_called_once_with(
                self.profile.context, wallet_record, {"wallet.key": "test_key"}
            )
            remove_wallet_profile.assert_called_once_with(wallet_profile)
            assert wallet_delete_record.call_count == 1
            delete_all_records.assert_called_once_with(
                RouteRecord.RECORD_TYPE, {"wallet_id": "test"}
            )

    async def test_create_auth_token_fails_no_wallet_key_but_required(self):
        self.profile.settings["multitenant.jwt_secret"] = "very_secret_jwt"
        wallet_record = WalletRecord(
            wallet_id="test_wallet",
            key_management_mode=WalletRecord.MODE_UNMANAGED,
            settings={"wallet.type": "indy"},
        )

        with self.assertRaises(WalletKeyMissingError):
            await self.manager.create_auth_token(wallet_record)

    async def test_create_auth_token_managed(self):
        self.profile.settings["multitenant.jwt_secret"] = "very_secret_jwt"
        wallet_record = mock.MagicMock(
            wallet_id="test_wallet",
            key_management_mode=WalletRecord.MODE_MANAGED,
            requires_external_key=False,
            settings={},
            save=mock.CoroutineMock(),
        )

        utc_now = datetime(2020, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        iat = int(round(utc_now.timestamp()))

        expected_token = jwt.encode(
            {"wallet_id": wallet_record.wallet_id, "iat": iat}, "very_secret_jwt"
        )

        with mock.patch.object(test_module, "datetime") as mock_datetime:
            mock_datetime.now.return_value = utc_now
            token = await self.manager.create_auth_token(wallet_record)

        assert wallet_record.jwt_iat == iat
        assert expected_token == token

    async def test_create_auth_token_unmanaged(self):
        self.profile.settings["multitenant.jwt_secret"] = "very_secret_jwt"
        wallet_record = mock.MagicMock(
            wallet_id="test_wallet",
            key_management_mode=WalletRecord.MODE_UNMANAGED,
            requires_external_key=True,
            settings={"wallet.type": "indy"},
            save=mock.CoroutineMock(),
        )

        utc_now = datetime(2020, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        iat = int(round(utc_now.timestamp()))

        expected_token = jwt.encode(
            {
                "wallet_id": wallet_record.wallet_id,
                "iat": iat,
                "wallet_key": "test_key",
            },
            "very_secret_jwt",
        )

        with mock.patch.object(test_module, "datetime") as mock_datetime:
            mock_datetime.now.return_value = utc_now
            token = await self.manager.create_auth_token(wallet_record, "test_key")

        assert wallet_record.jwt_iat == iat
        assert expected_token == token

    async def test_get_wallet_details_from_token(self):
        self.profile.settings["multitenant.jwt_secret"] = "very_secret_jwt"
        wallet_record = WalletRecord(
            key_management_mode=WalletRecord.MODE_MANAGED,
            settings={"wallet.type": "indy", "wallet.key": "wallet_key"},
            jwt_iat=100,
        )
        session = await self.profile.session()
        await wallet_record.save(session)
        token = jwt.encode(
            {"wallet_id": wallet_record.wallet_id, "iat": 100},
            "very_secret_jwt",
            algorithm="HS256",
        )
        ret_wallet_id, ret_wallet_key = self.manager.get_wallet_details_from_token(token)
        assert ret_wallet_id == wallet_record.wallet_id
        assert not ret_wallet_key

        token = jwt.encode(
            {
                "wallet_id": wallet_record.wallet_id,
                "iat": 100,
                "wallet_key": "wallet_key",
            },
            "very_secret_jwt",
            algorithm="HS256",
        )
        ret_wallet_id, ret_wallet_key = self.manager.get_wallet_details_from_token(token)
        assert ret_wallet_id == wallet_record.wallet_id
        assert ret_wallet_key == "wallet_key"

    async def test_get_wallet_and_profile(self):
        self.profile.settings["multitenant.jwt_secret"] = "very_secret_jwt"
        wallet_record = WalletRecord(
            key_management_mode=WalletRecord.MODE_MANAGED,
            settings={"wallet.type": "indy", "wallet.key": "wallet_key"},
            jwt_iat=100,
        )

        session = await self.profile.session()
        await wallet_record.save(session)

        with mock.patch.object(self.manager, "get_wallet_profile"):
            wallet, _ = await self.manager.get_wallet_and_profile(
                self.profile.context, wallet_record.wallet_id, "wallet_key"
            )
            assert wallet == wallet_record

    async def test_get_profile_for_token_invalid_token_raises(self):
        self.profile.settings["multitenant.jwt_secret"] = "very_secret_jwt"

        token = jwt.encode({"wallet_id": "test"}, "some_random_key")

        with self.assertRaises(jwt.InvalidTokenError):
            await self.manager.get_profile_for_token(self.profile.context, token)

    async def test_get_profile_for_token_wallet_key_missing_raises(self):
        self.profile.settings["multitenant.jwt_secret"] = "very_secret_jwt"
        wallet_record = WalletRecord(
            key_management_mode=WalletRecord.MODE_UNMANAGED,
            settings={"wallet.type": "indy"},
        )
        session = await self.profile.session()
        await wallet_record.save(session)
        token = jwt.encode(
            {"wallet_id": wallet_record.wallet_id}, "very_secret_jwt", algorithm="HS256"
        )

        with self.assertRaises(WalletKeyMissingError):
            await self.manager.get_profile_for_token(self.profile.context, token)

    async def test_get_profile_for_token_managed_wallet_no_iat(self):
        self.profile.settings["multitenant.jwt_secret"] = "very_secret_jwt"
        wallet_record = WalletRecord(
            key_management_mode=WalletRecord.MODE_MANAGED,
            settings={"wallet.type": "indy", "wallet.key": "wallet_key"},
        )

        session = await self.profile.session()
        await wallet_record.save(session)

        token = jwt.encode(
            {"wallet_id": wallet_record.wallet_id}, "very_secret_jwt", algorithm="HS256"
        )

        with mock.patch.object(self.manager, "get_wallet_profile") as get_wallet_profile:
            await self.manager.get_profile_for_token(self.profile.context, token)

            get_wallet_profile.assert_called_once_with(
                self.profile.context,
                wallet_record,
                {},
            )

    async def test_get_profile_for_token_managed_wallet_iat(self):
        iat = 100

        self.profile.settings["multitenant.jwt_secret"] = "very_secret_jwt"
        wallet_record = WalletRecord(
            key_management_mode=WalletRecord.MODE_MANAGED,
            settings={"wallet.type": "indy", "wallet.key": "wallet_key"},
            jwt_iat=iat,
        )

        session = await self.profile.session()
        await wallet_record.save(session)

        token = jwt.encode(
            {"wallet_id": wallet_record.wallet_id, "iat": iat},
            "very_secret_jwt",
            algorithm="HS256",
        )

        with mock.patch.object(self.manager, "get_wallet_profile") as get_wallet_profile:
            await self.manager.get_profile_for_token(self.profile.context, token)

            get_wallet_profile.assert_called_once_with(
                self.profile.context,
                wallet_record,
                {},
            )

    async def test_get_profile_for_token_managed_wallet_x_iat_no_match(self):
        iat = 100

        self.profile.settings["multitenant.jwt_secret"] = "very_secret_jwt"
        wallet_record = WalletRecord(
            key_management_mode=WalletRecord.MODE_MANAGED,
            settings={"wallet.type": "indy", "wallet.key": "wallet_key"},
            jwt_iat=iat,
        )

        session = await self.profile.session()
        await wallet_record.save(session)

        token = jwt.encode(
            # Change iat from record value
            {"wallet_id": wallet_record.wallet_id, "iat": 200},
            "very_secret_jwt",
            algorithm="HS256",
        )

        with (
            mock.patch.object(self.manager, "get_wallet_profile") as get_wallet_profile,
            self.assertRaises(MultitenantManagerError, msg="Token not valid"),
        ):
            await self.manager.get_profile_for_token(self.profile.context, token)

            get_wallet_profile.assert_called_once_with(
                self.profile.context,
                wallet_record,
                {},
            )

    async def test_get_profile_for_token_unmanaged_wallet(self):
        self.profile.settings["multitenant.jwt_secret"] = "very_secret_jwt"
        wallet_record = WalletRecord(
            key_management_mode=WalletRecord.MODE_UNMANAGED,
            settings={"wallet.type": "indy"},
        )

        session = await self.profile.session()
        await wallet_record.save(session)

        token = jwt.encode(
            {"wallet_id": wallet_record.wallet_id, "wallet_key": "wallet_key"},
            "very_secret_jwt",
            algorithm="HS256",
        )

        with mock.patch.object(self.manager, "get_wallet_profile") as get_wallet_profile:
            await self.manager.get_profile_for_token(
                self.profile.context,
                token,
            )

            get_wallet_profile.assert_called_once_with(
                self.profile.context,
                wallet_record,
                {"wallet.key": "wallet_key"},
            )

    async def test_get_wallets_by_message_missing_wire_format_raises(self):
        with self.assertRaises(
            InjectionError,
        ):
            await self.manager.get_wallets_by_message({})

    async def test_get_wallets_by_message(self):
        message_body = mock.MagicMock()
        recipient_keys = ["1", "2", "3", "4"]

        mock_wire_format = mock.MagicMock(
            get_recipient_keys=lambda message_body: recipient_keys
        )

        return_wallets = [
            WalletRecord(settings={}),
            None,
            None,
            WalletRecord(settings={}),
        ]

        with mock.patch.object(self.manager, "_get_wallet_by_key") as get_wallet_by_key:
            get_wallet_by_key.side_effect = return_wallets

            wallets = await self.manager.get_wallets_by_message(
                message_body, mock_wire_format
            )

            assert len(wallets) == 2
            assert wallets[0] == return_wallets[0]
            assert wallets[1] == return_wallets[3]
            assert get_wallet_by_key.call_count == 4

    async def test_get_profile_for_key(self):
        mock_wallet = mock.MagicMock()
        mock_wallet.requires_external_key = False
        with (
            mock.patch.object(
                self.manager,
                "_get_wallet_by_key",
                mock.CoroutineMock(return_value=mock_wallet),
            ),
            mock.patch.object(
                self.manager, "get_wallet_profile", mock.CoroutineMock()
            ) as mock_get_wallet_profile,
        ):
            profile = await self.manager.get_profile_for_key(self.context, "test-verkey")
            assert profile == mock_get_wallet_profile.return_value
