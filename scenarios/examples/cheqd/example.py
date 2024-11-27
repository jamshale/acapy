"""Minimal reproducible example script.

This script is for you to use to reproduce a bug or demonstrate a feature.
"""

import asyncio
import json
from os import getenv

from acapy_controller import Controller
from acapy_controller.logging import logging_to_stdout

ISSUER = getenv("ISSUER", "http://issuer:3001")
HOLDER = getenv("HOLDER", "http://holder:3001")


def format_json(json_to_format):
    return json.dumps(json_to_format, indent=4)


async def create_did(issuer):
    """Create a DID on the Cheqd testnet."""
    did_create_result = await issuer.post("/did/cheqd/create")
    did = did_create_result.get("did")

    assert did, "DID creation failed."
    assert did_create_result.get("verkey"), "Verkey is missing in DID creation result."

    print(f"Created DID: {did}")
    return did


async def resolve_did(issuer, did):
    """Resolve the DID document."""
    resolution_result = await issuer.get(f"/resolver/resolve/{did}")
    did_document = resolution_result.get("did_document")

    assert did_document, "DID document resolution failed."
    print(f"Resolved DID Document: {format_json(did_document)}")
    return did_document


async def update_did(issuer, did, did_document):
    """Update the DID document by adding a service endpoint."""
    service = [
        {
            "id": f"{did}#service-1",
            "type": "MessagingService",
            "serviceEndpoint": ["https://example.com/service"],
        }
    ]
    did_document["service"] = service
    del did_document["@context"]

    did_update_result = await issuer.post(
        "/did/cheqd/update", json={"did": did, "didDocument": did_document}
    )
    updated_did_doc = did_update_result.get("didDocument")
    updated_did = did_update_result.get("did")

    assert updated_did == did, "DID mismatch after update."
    assert (
        "service" in updated_did_doc
    ), "Key 'service' is missing in updated DID document."
    assert (
        updated_did_doc["service"] == service
    ), "Service does not match the expected value!"

    print(f"Updated DID Document: {format_json(updated_did_doc)}")
    return updated_did_doc


async def create_schema(issuer, did):
    """Create a schema on the Cheqd testnet."""
    schema_create_result = await issuer.post(
        "/anoncreds/schema",
        json={
            "schema": {
                "attrNames": ["score"],
                "issuerId": did,
                "name": "Example schema",
                "version": "1.0",
            }
        },
    )

    assert (
        schema_create_result.get("schema_state", {}).get("state") == "finished"
    ), "Schema state is not finished."

    schema_state = schema_create_result.get("schema_state", {})
    assert "schema_id" in schema_state, "Key 'schema_id' is missing in schema_state."

    schema_id = schema_state.get("schema_id")
    assert (
        did in schema_id
    ), f"schema_id does not contain the expected DID. Expected '{did}' in '{schema_id}'."

    print(f"Created schema: {format_json(schema_create_result)}")
    return schema_id


async def main():
    """Test DID Cheqd workflow."""
    async with Controller(base_url=ISSUER) as issuer:
        """
            This section of the test script demonstrates the CRUD operations of a did
            followed by creating schema, credential definition and credential issuance.
        """
        did = await create_did(issuer)
        did_document = await resolve_did(issuer, did)
        await update_did(issuer, did, did_document)
        await create_schema(issuer, did)

        # Credential Definition, Deactivate DID


if __name__ == "__main__":
    logging_to_stdout()
    asyncio.run(main())
