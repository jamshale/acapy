"""Minimal reproducible example script.

This script is for you to use to reproduce a bug or demonstrate a feature.
"""

import asyncio
from os import getenv

from acapy_controller import Controller
from acapy_controller.logging import logging_to_stdout

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

        print(did)

        # Resolve
        resolution_result = await issuer.get(
            f"/resolver/resolve/{did}",
        )
        did_document = resolution_result.get("did_document")
        assert did_document
        print(did_document)

        # Update: Add a service endpoint
        did_document["service"] = [
            {
                "id": f"{did}#service-1",
                "type": "MessagingService",
                "serviceEndpoint": ["https://example.com/service"],
            }
        ]
        did_document["@context"] = []
        did_update_result = await issuer.post(
            "/did/cheqd/update", json={"didDocument": did_document}
        )
        updated_did_doc = did_update_result.get("didDocument")
        print(updated_did_doc)
        updated_did = did_update_result.get("did")
        assert did == updated_did
        assert "service" in updated_did_doc, "Key 'metadata' is missing"
        assert isinstance(updated_did_doc["service"], dict)

        # Create Schema

        # Create Credential Definition

        # Deactivate the DID


if __name__ == "__main__":
    logging_to_stdout()
    asyncio.run(main())
