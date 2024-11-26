"""Minimal reproducible example script.

This script is for you to use to reproduce a bug or demonstrate a feature.
"""

import asyncio
from os import getenv

from acapy_controller import Controller
from acapy_controller import logging_to_stdout

ISSUER = getenv("ISSUER", "http://issuer:3001")
HOLDER = getenv("HOLDER", "http://holder:3001")


async def main():
    """Test DID Cheqd workflow."""
    async with Controller(base_url=ISSUER) as issuer:
        """
            This section of the test script demonstrates the CRUD operations of a did
            followed by creating schema, credential definition and credential issuance.
        """

        # Creating a did:cheqd on testnet
        did_create_result = await issuer.post("/did/cheqd/create")
        did = did_create_result.get("did")
        assert did
        assert did_create_result.get("verkey")

        # Resolve
        resolution_result = await issuer.get(
            "/resolver/resolve",
            params={
                "did": did,
            },
        )
        did_document = resolution_result.get("didDocument")
        assert did_document

        # Update: Add a service endpoint

        # Create Schema

        # Create Credential Definition

        # Deactivate the DID


if __name__ == "__main__":
    logging_to_stdout()
    asyncio.run(main())
