"""Cheqd DID Resolver."""

import json

from aiohttp import ClientSession
from pydid import DIDDocument
from typing import Optional, Pattern, Sequence, Text

from ...messaging.valid import CheqdDID
from ...config.injection_context import InjectionContext
from ...core.profile import Profile
from ..base import BaseDIDResolver, DIDNotFound, ResolverError, ResolverType


class CheqdDIDResolver(BaseDIDResolver):
    """Cheqd DID Resolver."""

    DID_RESOLVER_BASE_URL = "https://resolver.cheqd.net/1.0/identifiers/"

    def __init__(self):
        """Initialize Cheqd Resolver."""
        super().__init__(ResolverType.NATIVE)

    async def setup(self, context: InjectionContext):
        """Perform required setup for Cheqd DID resolution."""

    @property
    def supported_did_regex(self) -> Pattern:
        """Return supported_did_regex of Cheqd DID Resolver."""
        return CheqdDID.PATTERN

    async def _resolve(
        self,
        profile: Profile,
        did: str,
        service_accept: Optional[Sequence[Text]] = None,
    ) -> dict:
        """Resolve a Cheqd DID."""
        async with ClientSession() as session:
            async with session.get(
                self.DID_RESOLVER_BASE_URL + did,
            ) as response:
                if response.status == 200:
                    try:
                        # Validate DIDDoc with pyDID
                        resolver_resp = await response.json()
                        did_doc_resp = resolver_resp.get("didDocument")

                        did_doc = DIDDocument.from_json(json.dumps(did_doc_resp))
                        return did_doc.serialize()
                    except Exception as err:
                        raise ResolverError("Response was incorrectly formatted") from err
                if response.status == 404:
                    raise DIDNotFound(f"No document found for {did}")
            raise ResolverError(
                "Could not find doc for {}: {}".format(did, await response.text())
            )
