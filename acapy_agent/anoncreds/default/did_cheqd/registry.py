"""DID Indy Registry."""

import logging
from typing import Optional, Pattern, Sequence
from aiohttp import web
from pydantic.v1 import UUID4
from uuid_utils.compat import uuid4

from ..legacy_indy.registry import FAILED_TO_STORE_TRANSACTION_RECORD
from ....config.injection_context import InjectionContext
from ....core.profile import Profile
from ...base import (
    BaseAnonCredsRegistrar,
    BaseAnonCredsResolver,
    AnonCredsRegistrationError,
)
from ...models.anoncreds_cred_def import CredDef, CredDefResult, GetCredDefResult
from ...models.anoncreds_revocation import (
    GetRevListResult,
    GetRevRegDefResult,
    RevList,
    RevListResult,
    RevRegDef,
    RevRegDefResult,
)
from ...models.anoncreds_schema import (
    AnonCredsSchema,
    GetSchemaResult,
    SchemaResult,
    SchemaState,
)
from ....did.cheqd.cheqd_manager import DidCheqdManager
from ....messaging.valid import CheqdDID
from ....wallet.base import BaseWallet
from ....wallet.util import b64_to_bytes, bytes_to_b64

LOGGER = logging.getLogger(__name__)


class DIDCheqdRegistry(BaseAnonCredsResolver, BaseAnonCredsRegistrar):
    """DIDCheqdRegistry."""

    def __init__(self):
        """Initialize an instance.

        Args:
            None

        """

    @property
    def supported_identifiers_regex(self) -> Pattern:
        """Supported Identifiers regex."""
        return CheqdDID.PATTERN

    @staticmethod
    def make_schema_id(schema: AnonCredsSchema, resource_id: UUID4) -> str:
        """Derive the ID for a schema."""
        return f"{schema.issuer_id}/resources/{resource_id}"

    async def setup(self, context: InjectionContext):
        """Setup."""
        print("Successfully registered DIDCheqdRegistry")

    async def get_schema(self, profile: Profile, schema_id: str) -> GetSchemaResult:
        """Get a schema from the registry."""
        raise NotImplementedError()

    async def register_schema(
        self,
        profile: Profile,
        schema: AnonCredsSchema,
        options: Optional[dict] = None,
    ) -> SchemaResult:
        """Register a schema on the registry."""
        resource_id = options.get("resource_id") or uuid4()
        resource_type = "anoncredsSchema"
        resource_version = schema.version
        resource_name = schema.name

        schema_id = self.make_schema_id(schema, resource_id)
        LOGGER.debug("Registering schema: %s", schema_id)
        cheqd_schema = {
            "id": resource_id,
            "name": resource_name,
            "resourceType": resource_type,
            "version": resource_version,
            "data": {
                "name": f"{schema.name}",
                "version": f"{schema.version}",
                "attrNames": f"{schema.attr_names}",
            },
        }
        LOGGER.debug("schema value: %s", cheqd_schema)
        try:
            await self._create_and_publish_resource(
                profile,
                schema.issuer_id,
                cheqd_schema,
            )
        except Exception:
            raise AnonCredsRegistrationError(FAILED_TO_STORE_TRANSACTION_RECORD)
        return SchemaResult(
            job_id=uuid4().hex,
            schema_state=SchemaState(
                state=SchemaState.STATE_FINISHED,
                schema_id=schema_id,
                schema=schema,
            ),
            registration_metadata={
                "resource_id": resource_id,
                "resource_name": resource_name,
                "resource_type": resource_type,
                "resource_version": resource_version,
            },
        )

    async def get_credential_definition(
        self, profile: Profile, credential_definition_id: str
    ) -> GetCredDefResult:
        """Get a credential definition from the registry."""
        raise NotImplementedError()

    async def register_credential_definition(
        self,
        profile: Profile,
        schema: GetSchemaResult,
        credential_definition: CredDef,
        options: Optional[dict] = None,
    ) -> CredDefResult:
        """Register a credential definition on the registry."""
        raise NotImplementedError()

    async def get_revocation_registry_definition(
        self, profile: Profile, revocation_registry_id: str
    ) -> GetRevRegDefResult:
        """Get a revocation registry definition from the registry."""
        raise NotImplementedError()

    async def register_revocation_registry_definition(
        self,
        profile: Profile,
        revocation_registry_definition: RevRegDef,
        options: Optional[dict] = None,
    ) -> RevRegDefResult:
        """Register a revocation registry definition on the registry."""
        raise NotImplementedError()

    async def get_revocation_list(
        self,
        profile: Profile,
        revocation_registry_id: str,
        timestamp_from: Optional[int] = 0,
        timestamp_to: Optional[int] = None,
    ) -> GetRevListResult:
        """Get a revocation list from the registry."""
        raise NotImplementedError()

    async def register_revocation_list(
        self,
        profile: Profile,
        rev_reg_def: RevRegDef,
        rev_list: RevList,
        options: Optional[dict] = None,
    ) -> RevListResult:
        """Register a revocation list on the registry."""
        raise NotImplementedError()

    async def update_revocation_list(
        self,
        profile: Profile,
        rev_reg_def: RevRegDef,
        prev_list: RevList,
        curr_list: RevList,
        revoked: Sequence[int],
        options: Optional[dict] = None,
    ) -> RevListResult:
        """Update a revocation list on the registry."""
        raise NotImplementedError()

    @staticmethod
    async def _create_and_publish_resource(profile: Profile, did: str, options: dict):
        """Create, Sign and Publish a Resource."""
        cheqd_manager = DidCheqdManager(profile)
        async with profile.session() as session:
            wallet = session.inject_or(BaseWallet)
            if not wallet:
                raise web.HTTPForbidden(reason="No wallet available")

            try:
                # validate issuer_id
                did_record = await wallet.get_local_did(did)
                verkey = did_record.verkey

                # request create resource operation
                create_request_res = await cheqd_manager.registrar.create_resource(
                    did, options
                )

                job_id: str = create_request_res.get("jobId")
                resource_state = create_request_res.get("resourceState")
                if resource_state.get("state") == "action":
                    sign_req: dict = resource_state.get("signingRequest")[0]
                    kid: str = sign_req.get("kid")
                    payload_to_sign: str = sign_req.get("serializedPayload")
                    # sign payload
                    signature_bytes = await wallet.sign_message(
                        b64_to_bytes(payload_to_sign), verkey
                    )
                    # publish resource
                    publish_resource_res = await cheqd_manager.registrar.create_resource(
                        did,
                        {
                            "jobId": job_id,
                            "secret": {
                                "signingResponse": [
                                    {
                                        "kid": kid,
                                        "signature": bytes_to_b64(signature_bytes),
                                    }
                                ],
                            },
                        },
                    )
                    resource_state = publish_resource_res.get("resourceState")
                    if resource_state.get("state") != "finished":
                        raise AnonCredsRegistrationError(
                            f"Error publishing Resource {resource_state.get("reason")}"
                        )
                else:
                    raise AnonCredsRegistrationError(
                        f"Error publishing Resource {resource_state.get("reason")}"
                    )
            except Exception:
                raise AnonCredsRegistrationError(FAILED_TO_STORE_TRANSACTION_RECORD)
