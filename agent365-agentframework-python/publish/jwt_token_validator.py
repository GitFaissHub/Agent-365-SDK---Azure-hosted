import asyncio
import logging
import jwt
from jwt import PyJWKClient, decode, get_unverified_header

# You may need to adjust these imports based on your project structure
# from .agent_auth_configuration import AgentAuthConfiguration
# from .claims_identity import ClaimsIdentity

logger = logging.getLogger(__name__)

class JwtTokenValidator:
    def __init__(self, configuration):
        self.configuration = configuration
        # Use MicrosoftAppIdUri from environment or config for audience validation
        import os
        self.CLIENT_ID_URI = os.getenv("MICROSOFTAPPIDURI") or getattr(configuration, "MicrosoftAppIdUri", None)
        self.CLIENT_ID = os.getenv("MicrosoftAppId") or getattr(configuration, "MicrosoftAppId", None)

    async def validate_token(self, token: str):
        logger.debug("Validating JWT token.")
        key = await self._get_public_key_or_secret(token)
        decoded_token = jwt.decode(
            token,
            key=key,
            algorithms=["RS256"],
            leeway=300.0,
            options={"verify_aud": False},
        )
        expected_aud_values = [self.CLIENT_ID_URI, self.CLIENT_ID]
        if decoded_token["aud"] not in expected_aud_values:
            logger.error(f"Invalid audience: {decoded_token['aud']} (expected one of: {expected_aud_values})", stack_info=True)
            raise ValueError(f"Invalid audience. Got: {decoded_token['aud']}, expected one of: {expected_aud_values}")
        logger.debug("JWT token validated successfully.")
        # Return your ClaimsIdentity or decoded_token as needed
        return decoded_token

    def get_anonymous_claims(self):
        logger.debug("Returning anonymous claims identity.")
        return {}

    async def _get_public_key_or_secret(self, token: str):
        header = get_unverified_header(token)
        unverified_payload: dict = decode(token, options={"verify_signature": False})
        jwksUri = (
            "https://login.botframework.com/v1/.well-known/keys"
            if unverified_payload.get("iss") == "https://api.botframework.com"
            else f"https://login.microsoftonline.com/{self.configuration.TENANT_ID}/discovery/v2.0/keys"
        )
        jwks_client = PyJWKClient(jwksUri)
        key = await asyncio.to_thread(jwks_client.get_signing_key, header["kid"])
        return key
