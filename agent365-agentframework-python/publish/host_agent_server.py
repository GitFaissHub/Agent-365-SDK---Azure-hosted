# Copyright (c) Microsoft. All rights reserved.

"""Generic Agent Host Server - Hosts agents implementing AgentInterface"""

# --- Imports ---
import logging
import os
import socket

from azure.identity import DefaultAzureCredential
from os import environ

from aiohttp.web import Application, Request, Response, json_response, run_app
from aiohttp.web_middlewares import middleware as web_middleware
from dotenv import load_dotenv
from agent_interface import AgentInterface, check_agent_inheritance
from microsoft_agents.activity import load_configuration_from_env, Activity, ActivityTypes
from microsoft_agents.authentication.msal import MsalConnectionManager
from microsoft_agents.hosting.aiohttp import (
    CloudAdapter,
    start_agent_process,
)
from custom_jwt_authorization_middleware import custom_jwt_authorization_middleware
from microsoft_agents.hosting.core import (
    AgentApplication,
    AgentAuthConfiguration,
    AuthenticationConstants,
    Authorization,
    ClaimsIdentity,
    MemoryStorage,
    TurnContext,
    TurnState,
)


from microsoft_agents_a365.observability.core.config import configure
from microsoft_agents_a365.observability.core.middleware.baggage_builder import (
    BaggageBuilder,
)
from microsoft_agents_a365.runtime.environment_utils import (
    get_observability_authentication_scope,
)

from microsoft_agents_a365.notifications import NotificationTypes, EmailResponse, AgentNotification
from microsoft_agents_a365.notifications.models import AgentNotificationActivity
from microsoft_agents.activity import ChannelId
from token_cache import cache_agentic_token

# --- Configuration ---
ms_agents_logger = logging.getLogger("microsoft_agents")
ms_agents_logger.addHandler(logging.StreamHandler())
ms_agents_logger.setLevel(logging.INFO)

observability_logger = logging.getLogger("microsoft_agents_a365.observability")
observability_logger.setLevel(logging.ERROR)

logger = logging.getLogger(__name__)

load_dotenv()
agents_sdk_config = load_configuration_from_env(environ)


# --- Public API ---
def create_and_run_host(
    agent_class: type[AgentInterface], *agent_args, **agent_kwargs
):
    """Create and run a generic agent host"""
    if not check_agent_inheritance(agent_class):
        raise TypeError(
            f"Agent class {agent_class.__name__} must inherit from AgentInterface"
        )

    configure(
        service_name="AgentFrameworkTracingWithAzureOpenAI",
        service_namespace="AgentFrameworkTesting",
    )

    host = GenericAgentHost(agent_class, *agent_args, **agent_kwargs)
    auth_config = host.create_auth_configuration()
    host.start_server(auth_config)


# --- Generic Agent Host ---
class GenericAgentHost:
    """Generic host for agents implementing AgentInterface"""

    # --- Initialization ---
    def __init__(self, agent_class: type[AgentInterface], *agent_args, **agent_kwargs):
        if not check_agent_inheritance(agent_class):
            raise TypeError(
                f"Agent class {agent_class.__name__} must inherit from AgentInterface"
            )

        # Auth handler name can be configured via environment
        # Defaults to empty (no auth handler) - set AUTH_HANDLER_NAME=AGENTIC for production agentic auth
        self.auth_handler_name = os.getenv("AUTH_HANDLER_NAME", "") or None
        if self.auth_handler_name:
            logger.info(f"🔐 Using auth handler: {self.auth_handler_name}")
        else:
            logger.info("🔓 No auth handler configured (AUTH_HANDLER_NAME not set)")

        self.agent_class = agent_class
        self.agent_args = agent_args
        self.agent_kwargs = agent_kwargs
        self.agent_instance = None

        self.storage = MemoryStorage()
        self.connection_manager = MsalConnectionManager(**agents_sdk_config)
        self.adapter = CloudAdapter(connection_manager=self.connection_manager)
        self.authorization = Authorization(
            self.storage, self.connection_manager, **agents_sdk_config
        )
        self.agent_app = AgentApplication[TurnState](
            storage=self.storage,
            adapter=self.adapter,
            authorization=self.authorization,
            **agents_sdk_config,
        )
        self.agent_notification = AgentNotification(self.agent_app)
        self._setup_handlers()
        # logger.info("✅ Notification handlers registered successfully")

    # --- Observability ---
    async def _setup_observability_token(
        self, context: TurnContext, tenant_id: str, agent_id: str
    ):
        # Only attempt token exchange when auth handler is configured
        if not self.auth_handler_name:
            logger.debug("Skipping observability token exchange (no auth handler)")
            return
            
        try:
            logger.info(
                f"🔐 Attempting token exchange for observability... "
                f"(tenant_id={tenant_id}, agent_id={agent_id})"
            )
            exaau_token = await self.agent_app.auth.exchange_token(
                context,
                scopes=get_observability_authentication_scope(),
                auth_handler_id=self.auth_handler_name,
            )
            cache_agentic_token(tenant_id, agent_id, exaau_token.token)
            logger.info(
                f"✅ Token exchange successful "
                f"(tenant_id={tenant_id}, agent_id={agent_id})"
            )
        except Exception as e:
            logger.warning(f"⚠️ Failed to cache observability token: {e}")

    async def _validate_agent_and_setup_context(self, context: TurnContext):
        logger.info("🔍 Validating agent and setting up context...")
        tenant_id = context.activity.recipient.tenant_id
        agent_id = context.activity.recipient.agentic_app_id
        logger.info(f"🔍 tenant_id={tenant_id}, agent_id={agent_id}")

        if not self.agent_instance:
            logger.error("Agent not available")
            await context.send_activity("❌ Sorry, the agent is not available.")
            return None

        await self._setup_observability_token(context, tenant_id, agent_id)
        return tenant_id, agent_id

    # --- Handlers (Messages & Notifications) ---

    def _setup_handlers(self):
        """Setup message and conversationUpdate handlers for the agent."""
        handler_config = {"auth_handlers": [self.auth_handler_name]} if self.auth_handler_name else {}

        async def on_message(context: TurnContext, _: TurnState):
            try:
                result = await self._validate_agent_and_setup_context(context)
                if result is None:
                    return
                tenant_id, agent_id = result
                with BaggageBuilder().tenant_id(tenant_id).agent_id(agent_id).build():
                    user_message = context.activity.text or ""
                    if not user_message.strip():
                        return
                    logger.info(f"📨 {user_message}")
                    response = await self.agent_instance.process_user_message(
                        user_message, self.agent_app.auth, self.auth_handler_name, context
                    )
                    await context.send_activity(response)
            except Exception as e:
                logger.error(f"❌ Error: {e}")
                await context.send_activity(f"Sorry, I encountered an error: {str(e)}")

        async def on_conversation_update(context: TurnContext, _: TurnState):
            await context.send_activity(
                f"👋 Welcome! I'm {self.agent_class.__name__}. How can I help you today?"
            )

        self.agent_app.activity("message", **handler_config)(on_message)
        self.agent_app.conversation_update("membersAdded", **handler_config)(on_conversation_update)

        @self.agent_notification.on_agent_notification(
            channel_id=ChannelId(channel="agents", sub_channel="*"),
            **handler_config,
        )
        async def on_notification(
            context: TurnContext,
            state: TurnState,
            notification_activity: AgentNotificationActivity,
        ):
            try:
                result = await self._validate_agent_and_setup_context(context)
                if result is None:
                    return
                tenant_id, agent_id = result

                with BaggageBuilder().tenant_id(tenant_id).agent_id(agent_id).build():
                    logger.info(f"📬 {notification_activity.notification_type}")

                    if not hasattr(
                        self.agent_instance, "handle_agent_notification_activity"
                    ):
                        logger.warning("⚠️ Agent doesn't support notifications")
                        await context.send_activity(
                            "This agent doesn't support notification handling yet."
                        )
                        return

                    response = (
                        await self.agent_instance.handle_agent_notification_activity(
                            notification_activity, self.agent_app.auth, self.auth_handler_name, context
                        )
                    )

                    if notification_activity.notification_type == NotificationTypes.EMAIL_NOTIFICATION:
                        response_activity = EmailResponse.create_email_response_activity(response)
                        await context.send_activity(response_activity)
                        return

                    await context.send_activity(response)

            except Exception as e:
                logger.error(f"❌ Notification error: {e}")
                await context.send_activity(
                    f"Sorry, I encountered an error processing the notification: {str(e)}"
                )

    # --- Agent Initialization ---
    async def initialize_agent(self, app=None):
        if self.agent_instance is None:
            logger.info(f"🤖 Initializing {self.agent_class.__name__}...")
            self.agent_instance = self.agent_class(*self.agent_args, **self.agent_kwargs)
            await self.agent_instance.initialize()

    # --- Authentication ---
    def create_auth_configuration(self) -> AgentAuthConfiguration | None:
        client_id = environ.get("CLIENT_ID")
        tenant_id = environ.get("TENANT_ID")
        client_secret = environ.get("CLIENT_SECRET")

        if client_id and tenant_id and client_secret:
            logger.info("🔒 Using Client Credentials authentication")
            return AgentAuthConfiguration(
                client_id=client_id,
                tenant_id=tenant_id,
                client_secret=client_secret,
                scopes=["5a807f24-c9de-44ee-a3a7-329e88a00ffc/.default"],
            )

        # Use DefaultAzureCredential for local dev and managed identity in Azure
        try:
            credential = DefaultAzureCredential()
            logger.info("🔒 Using DefaultAzureCredential (Managed Identity or local dev auth)")
            return AgentAuthConfiguration(
                credential=credential,
                scopes=["5a807f24-c9de-44ee-a3a7-329e88a00ffc/.default"],
            )
        except Exception as e:
            logger.warning(f"⚠️ DefaultAzureCredential not available: {e}")

        if environ.get("BEARER_TOKEN"):
            logger.info("🔑 Anonymous dev mode")
        else:
            logger.warning("⚠️ No auth env vars; running anonymous")
        return None

    # --- Server ---
    def start_server(self, auth_configuration: AgentAuthConfiguration | None = None):
        async def entry_point(req: Request) -> Response:
            return await start_agent_process(
                req, req.app["agent_app"], req.app["adapter"]
            )

        async def health(_req: Request) -> Response:
            return json_response(
                {
                    "status": "ok",
                    "agent_type": self.agent_class.__name__,
                    "agent_initialized": self.agent_instance is not None,
                }
            )

        middlewares = []
        if auth_configuration:
            middlewares.append(custom_jwt_authorization_middleware)

        @web_middleware
        async def anonymous_claims(request, handler):
            if not auth_configuration:
                request["claims_identity"] = ClaimsIdentity(
                    {
                        AuthenticationConstants.AUDIENCE_CLAIM: "anonymous",
                        AuthenticationConstants.APP_ID_CLAIM: "anonymous-app",
                    },
                    False,
                    "Anonymous",
                )
            return await handler(request)

        middlewares.append(anonymous_claims)
        app = Application(middlewares=middlewares)

        app.router.add_post("/api/messages", entry_point)
        app.router.add_get("/api/messages", lambda _: Response(status=200))
        app.router.add_get("/api/health", health)

        app["agent_configuration"] = auth_configuration
        app["agent_app"] = self.agent_app
        app["adapter"] = self.agent_app.adapter

        async def on_startup(app):
            logger.info("[LIFECYCLE] aiohttp server startup event triggered")
            await self.initialize_agent(app)
        async def on_shutdown(app):
            logger.info("[LIFECYCLE] aiohttp server shutdown event triggered")
            await self.cleanup(app)
        async def on_cleanup(app):
            logger.info("[LIFECYCLE] aiohttp server cleanup event triggered")
        app.on_startup.append(on_startup)
        app.on_shutdown.append(on_shutdown)
        app.on_cleanup.append(on_cleanup)

        desired_port = int(environ.get("PORT", 3978))
        port = desired_port

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            if s.connect_ex(("127.0.0.1", desired_port)) == 0:
                port = desired_port + 1

        print("=" * 80)
        print(f"🏢 {self.agent_class.__name__}")
        print("=" * 80)
        print(f"🔒 Auth: {'Enabled' if auth_configuration else 'Anonymous'}")
        print(f"🚀 Server: localhost:{port}")
        print(f"📚 Endpoint: http://localhost:{port}/api/messages")
        print(f"❤️  Health: http://localhost:{port}/api/health\n")

        try:
            run_app(app, host="0.0.0.0", port=port, handle_signals=False)
        except KeyboardInterrupt:
            print("\n👋 Server stopped")

    # --- Cleanup ---
    async def cleanup(self, app=None):
        if self.agent_instance:
            try:
                await self.agent_instance.cleanup()
            except Exception as e:
                logger.error(f"Cleanup error: {e}")



