"""DID manager for Cheqd."""

from aries_askar import AskarError, Key

from .registrar import DidCheqdRegistrar
from ...core.profile import Profile
from ...wallet.askar import CATEGORY_DID
from ...wallet.crypto import validate_seed
from ...wallet.did_method import CHEQD, DIDMethods
from ...wallet.did_parameters_validation import DIDParametersValidation
from ...wallet.error import WalletError
from ...wallet.key_type import ED25519, KeyType, KeyTypes
from ...wallet.util import bytes_to_b58, b64_to_bytes, bytes_to_b64


class DidCheqdManager:
    """DID manager for Cheqd."""

    registrar: DidCheqdRegistrar

    def __init__(self, profile: Profile) -> None:
        """Initialize the DID  manager."""
        self.profile = profile
        self.registrar = DidCheqdRegistrar()

    async def _get_key_type(self, key_type: str) -> KeyType:
        async with self.profile.session() as session:
            key_types = session.inject(KeyTypes)
            return key_types.from_key_type(key_type) or ED25519

    def _create_key_pair(self, options: dict, key_type: KeyType) -> Key:
        seed = options.get("seed")
        if seed and not self.profile.settings.get("wallet.allow_insecure_seed"):
            raise WalletError("Insecure seed is not allowed")

        if seed:
            seed = validate_seed(seed)
            return Key.from_secret_bytes(key_type, seed)
        return Key.generate(key_type)

    async def register(self, options: dict) -> dict:
        """Register a DID Cheqd."""
        options = options or {}

        key_type = await self._get_key_type(options.get("key_type") or ED25519)
        did_validation = DIDParametersValidation(self.profile.inject(DIDMethods))
        did_validation.validate_key_type(CHEQD, key_type)

        key_pair = self._create_key_pair(options, key_type.key_type)
        verkey_bytes = key_pair.get_public_bytes()
        verkey = bytes_to_b58(verkey_bytes)

        public_key_hex = verkey_bytes.hex()
        network = "testnet"

        try:
            # generate payload
            generate_res = await self.registrar.generate_did_doc(network, public_key_hex)
            if generate_res is None:
                raise WalletError("Error constructing DID Document")

            did_document = generate_res.get("didDoc")
            did: str = did_document.get("id")
            # request create did
            create_request_res = await self.registrar.create(
                {"didDocument": did_document, "network": network}
            )

            job_id: str = create_request_res.get("jobId")
            did_state = create_request_res.get("didState")
            if did_state.get("state") == "action":
                sign_req: dict = did_state.get("signingRequest")[0]
                kid: str = sign_req.get("kid")
                payload_to_sign: str = sign_req.get("serializedPayload")
                # publish did
                publish_did_res = await self.registrar.create(
                    {
                        "jobId": job_id,
                        "network": network,
                        "secret": {
                            "signingResponse": [
                                {
                                    "kid": kid,
                                    "signature": bytes_to_b64(
                                        key_pair.sign_message(
                                            b64_to_bytes(payload_to_sign)
                                        )
                                    ),
                                }
                            ],
                        },
                    }
                )
                publish_did_state = publish_did_res.get("didState")
                if publish_did_state.get("state") != "finished":
                    raise WalletError("Error registering DID")
            else:
                raise WalletError("Error registering DID")
        except Exception:
            raise

        async with self.profile.session() as session:
            try:
                await session.handle.insert_key(verkey, key_pair)
                await session.handle.insert(
                    CATEGORY_DID,
                    did,
                    value_json={
                        "did": did,
                        "method": CHEQD.method_name,
                        "verkey": verkey,
                        "verkey_type": ED25519.key_type,
                        "metadata": {},
                    },
                    tags={
                        "method": CHEQD.method_name,
                        "verkey": verkey,
                        "verkey_type": ED25519.key_type,
                    },
                )
            except AskarError as err:
                raise WalletError(f"Error registering DID: {err}") from err

        return {
            "did": did,
            "verkey": verkey,
        }
