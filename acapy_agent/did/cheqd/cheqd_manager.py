"""DID manager for Cheqd."""

from aiohttp import web
from .registrar import DidCheqdRegistrar
from ...core.profile import Profile
from ...wallet.base import BaseWallet
from ...wallet.crypto import validate_seed
from ...wallet.did_method import CHEQD, DIDMethods
from ...wallet.did_parameters_validation import DIDParametersValidation
from ...wallet.error import WalletError
from ...wallet.key_type import ED25519
from ...wallet.util import b64_to_bytes, bytes_to_b64, b58_to_bytes


class DidCheqdManager:
    """DID manager for Cheqd."""

    registrar: DidCheqdRegistrar

    def __init__(self, profile: Profile) -> None:
        """Initialize the DID  manager."""
        self.profile = profile
        self.registrar = DidCheqdRegistrar()

    async def register(self, options: dict) -> dict:
        """Register a DID Cheqd."""
        options = options or {}

        seed = options.get("seed")
        if seed and not self.profile.settings.get("wallet.allow_insecure_seed"):
            raise WalletError("Insecure seed is not allowed")
        if seed:
            seed = validate_seed(seed)

        network = options.get("network") or "testnet"
        key_type = ED25519

        did_validation = DIDParametersValidation(self.profile.inject(DIDMethods))
        did_validation.validate_key_type(CHEQD, key_type)

        async with self.profile.session() as session:
            try:
                wallet = session.inject(BaseWallet)
                if not wallet:
                    raise web.HTTPForbidden(reason="No wallet available")

                key = await wallet.create_key(key_type, seed)
                verkey = key.verkey
                verkey_bytes = b58_to_bytes(verkey)
                public_key_hex = verkey_bytes.hex()

                # generate payload
                generate_res = await self.registrar.generate_did_doc(
                    network, public_key_hex
                )
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
                    sign_req: dict = did_state.get("signingRequest")
                    sign_res = []

                    for req in sign_req:
                        kid: str = req.get("kid")
                        payload_to_sign: str = req.get("serializedPayload")
                        signature_bytes = await wallet.sign_message(
                            b64_to_bytes(payload_to_sign), verkey
                        )
                        sign_res.append(
                            {
                                "kid": kid,
                                "signature": bytes_to_b64(signature_bytes),
                            }
                        )

                    # publish did
                    publish_did_res = await self.registrar.create(
                        {
                            "jobId": job_id,
                            "network": network,
                            "secret": {
                                "signingResponse": sign_res,
                            },
                        }
                    )
                    publish_did_state = publish_did_res.get("didState")
                    if publish_did_state.get("state") != "finished":
                        raise WalletError(
                            f"Error registering DID {publish_did_state.get("reason")}"
                        )
                else:
                    raise WalletError(f"Error registering DID {did_state.get("reason")}")

                # create public did record
                await wallet.create_public_did(CHEQD, key_type, seed, did)
                # assign verkey to kid
                await wallet.assign_kid_to_key(verkey, kid)
            except WalletError as err:
                raise WalletError(f"Error registering DID: {err}") from err
            except Exception:
                raise
        return {
            "did": did,
            "verkey": verkey,
        }
