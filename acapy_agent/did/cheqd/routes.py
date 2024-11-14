"""DID Cheqd routes."""

from http import HTTPStatus

from aiohttp import web
from aiohttp_apispec import docs, request_schema, response_schema
from marshmallow import Schema, fields

from ...admin.decorators.auth import tenant_authentication
from ...admin.request_context import AdminRequestContext
from ...did.cheqd.cheqd_manager import DidCheqdManager
from ...messaging.models.openapi import OpenAPISchema
from ...messaging.valid import CHEQD_DID_EXAMPLE, CHEQD_DID_VALIDATE
from ...wallet.error import WalletError


class CreateRequestSchema(OpenAPISchema):
    """Parameters and validators for create DID endpoint."""

    options = fields.Dict(
        required=False,
        metadata={
            "description": "Additional configuration options",
            "example": {
                "network": "testnet",
                "method_specific_id_algo": "uuid",
                "key_type": "ed25519",
            },
        },
    )
    features = fields.Dict(
        required=False,
        metadata={
            "description": "Additional features to enable for the did.",
            "example": "{}",
        },
    )


class CreateResponseSchema(OpenAPISchema):
    """Response schema for create DID endpoint."""

    did = fields.Str(
        metadata={
            "description": "DID created",
            "example": CHEQD_DID_EXAMPLE,
        }
    )
    verkey = fields.Str(
        metadata={
            "description": "Verification key",
            "example": "BnSWTUQmdYCewSGFrRUhT6LmKdcCcSzRGqWXMPnEP168",
        }
    )


class DeactivateRequestSchema(OpenAPISchema):
    """Parameters and validators for deactivate DID endpoint."""

    did = fields.Str(
        required=True,
        validate=CHEQD_DID_VALIDATE,
        metadata={"description": "DID to deactivate", "example": CHEQD_DID_EXAMPLE},
    )


class DeactivateResponseSchema(OpenAPISchema):
    """Response schema for deactivate DID endpoint."""

    did = fields.Str(
        validate=CHEQD_DID_VALIDATE,
        metadata={
            "description": "DID that has been deactivted",
            "example": CHEQD_DID_EXAMPLE,
        },
    )
    did_document = fields.Dict(
        required=False,
        allow_none=True,
        metadata={
            "description": "The DID document, if available, after deactivation. \
            For deactivated DIDs, this is usually set to None.",
        },
    )
    did_document_metadata = fields.Dict(
        required=True,
        metadata={
            "description": "Metadata related specific to the DID document, \
            indicating status changes. This typically includes a 'deactivated' status \
            flag to confirm the operation.",
        },
    )


class UpdateRequestSchema(OpenAPISchema):
    """Parameters and validators for update DID endpoint."""

    EXAMPLE = {
        "did": CHEQD_DID_EXAMPLE,
        "services": [
            {
                "id": CHEQD_DID_EXAMPLE + "#service-1",
                "type": "MessagingService",
                "serviceEndpoint": ["https://example.com/service"],
            }
        ],
        "verification_methods": [
            {
                "id": CHEQD_DID_EXAMPLE + "#key-1",
                "type": "Ed25519VerificationKey2018",
                "controller": CHEQD_DID_EXAMPLE,
                "publicKeyMultibase": "z6Mk...",
            }
        ],
        "authentications": [CHEQD_DID_EXAMPLE + "#key-1"],
    }

    did = fields.Str(
        required=True,
        validate=CHEQD_DID_VALIDATE,
        metadata={"description": "DID to update"},
    )
    services = fields.List(
        fields.Nested(
            Schema.from_dict(
                {
                    "id": fields.Str(
                        required=True,
                        metadata={"description": "Service ID"},
                    ),
                    "type": fields.Str(
                        required=True,
                        metadata={"description": "Service type"},
                    ),
                    "serviceEndpoint": fields.List(
                        fields.Str(metadata={"description": "Service endpoint URL"})
                    ),
                },
            ),
            required=True,
        )
    )
    verification_methods = fields.List(
        fields.Nested(
            Schema.from_dict(
                {
                    "id": fields.Str(
                        required=True,
                        metadata={"description": "Verification method ID"},
                    ),
                    "type": fields.Str(
                        required=True,
                        metadata={"description": "Verification method type"},
                    ),
                    "controller": fields.Str(
                        required=True,
                        metadata={"description": "Verification controller DID"},
                    ),
                    "publicKeyMultibase": fields.Str(
                        metadata={"description": "Public key in multibase format"}
                    ),
                },
            ),
            required=False,
        )
    )
    authentications = fields.List(
        fields.Str(
            required=True,
            metadata={"description": "Authentication method ID"},
        )
    )


class UpdateResponseSchema(OpenAPISchema):
    """Response schema for update DID endpoint."""

    did = fields.Str(
        validate=CHEQD_DID_VALIDATE,
        metadata={
            "description": "DID that has been updated",
            "example": CHEQD_DID_EXAMPLE,
        },
    )
    did_state = fields.Str(
        required=True,
        metadata={"description": "State of the did update", "example": "finished"},
    )


@docs(tags=["did"], summary="Create a did:cheqd")
@request_schema(CreateRequestSchema())
@response_schema(CreateResponseSchema, HTTPStatus.OK)
@tenant_authentication
async def create_cheqd_did(request: web.BaseRequest):
    """Create a Cheqd DID."""
    context: AdminRequestContext = request["context"]

    try:
        body = await request.json()
    except Exception:
        body = {}

    try:
        return web.json_response(
            (await DidCheqdManager(context.profile).register(body.get("options"))),
        )
    except WalletError as e:
        raise web.HTTPBadRequest(reason=str(e))


@docs(tags=["did"], summary="Update a did:cheqd")
@request_schema(UpdateRequestSchema(), example=UpdateRequestSchema.EXAMPLE)
@response_schema(UpdateResponseSchema, HTTPStatus.OK)
@tenant_authentication
async def update_cheqd_did(request: web.BaseRequest):
    """Update a Cheqd DID."""
    context: AdminRequestContext = request["context"]

    try:
        body = await request.json()
    except Exception:
        body = {}

    try:
        return web.json_response(
            (
                await DidCheqdManager(context.profile).update(
                    body.get("did"),
                    body.get("services"),
                    body.get("verification_methods", body.get("authentications")),
                )
            ),
        )
    except WalletError as e:
        raise web.HTTPBadRequest(reason=str(e))


@docs(tags=["did"], summary="Deactivate a did:cheqd")
@request_schema(DeactivateRequestSchema())
@response_schema(DeactivateResponseSchema, HTTPStatus.OK)
@tenant_authentication
async def deactivate_cheqd_did(request: web.BaseRequest):
    """Deactivate a Cheqd DID."""
    context: AdminRequestContext = request["context"]

    try:
        body = await request.json()
    except Exception:
        body = {}

    try:
        return web.json_response(
            (await DidCheqdManager(context.profile).deactivate(body.get("did"))),
        )
    except WalletError as e:
        raise web.HTTPBadRequest(reason=str(e))


async def register(app: web.Application):
    """Register routes."""
    app.add_routes(
        [
            web.post("/did/cheqd/create", create_cheqd_did),
            web.post("/did/cheqd/update", update_cheqd_did),
            web.post("/did/cheqd/deactivate", deactivate_cheqd_did),
        ]
    )


def post_process_routes(app: web.Application):
    """Amend swagger API."""
    # Add top-level tags description
    if "tags" not in app._state["swagger_dict"]:
        app._state["swagger_dict"]["tags"] = []
    app._state["swagger_dict"]["tags"].append(
        {
            "name": "did",
            "description": "Endpoints for managing dids",
            "externalDocs": {
                "description": "Specification",
                "url": "https://www.w3.org/TR/did-core/",
            },
        }
    )
