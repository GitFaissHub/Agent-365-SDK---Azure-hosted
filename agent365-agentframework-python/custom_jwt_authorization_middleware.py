import logging
from aiohttp.web_middlewares import middleware
from aiohttp.web import Request, Response
from jwt_token_validator import JwtTokenValidator
from microsoft_agents.hosting.core import (
    AuthenticationConstants,
    ClaimsIdentity,
)

logger = logging.getLogger(__name__)

@middleware
async def custom_jwt_authorization_middleware(request: Request, handler):
    # Extract token from Authorization header
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        logger.warning("No Bearer token found in Authorization header.")
        return await handler(request)
    token = auth_header[len("Bearer "):]

    # Use app config for validator
    app = request.app
    config = app.get("agent_configuration")
    if not config:
        logger.warning("No agent configuration found for JWT validation.")
        return await handler(request)

    validator = JwtTokenValidator(config)
    try:
        decoded = await validator.validate_token(token)
        claims_identity = ClaimsIdentity(
            decoded,
            True,
            "JWT"
        )
        request["claims_identity"] = claims_identity
        logger.info("JWT validated and claims identity set.")
    except Exception as e:
        logger.error(f"JWT validation failed: {e}")
        # Optionally, you could return a 401 here
        return Response(status=401, text="Unauthorized: Invalid JWT")

    return await handler(request)
