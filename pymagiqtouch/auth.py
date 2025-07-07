"""
Authentication handling for MagiqTouch API
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional

from mandate import Cognito

_LOGGER = logging.getLogger("pymagiqtouch.auth")


class CognitoAuth:
    """AWS Cognito authentication handler for MagiqTouch."""

    # Cognito parameters
    AWS_USER_POOL_ID = "ap-southeast-2_uw5VVNlib"
    CLIENT_ID = "afh7fftbb0fg2rnagdbgd9b7b"
    COGNITO_REGION = "ap-southeast-2"

    def __init__(
        self,
        username: str,
        password: str,
        logger: Optional[logging.Logger] = None
    ):
        """Initialize the Cognito authentication handler.

        Args:
            username: MagiqTouch account username
            password: MagiqTouch password
            logger: Optional custom logger
        """
        self.username = username
        self.password = password
        self.logger = logger or _LOGGER

        # Create the Cognito client
        self.cognito = Cognito(
            user_pool_id=self.AWS_USER_POOL_ID,
            client_id=self.CLIENT_ID,
            user_pool_region=self.COGNITO_REGION,
            username=self.username,
            # Dummy credentials to bypass EC2 IMDS
            access_key="AKIAIOSFODNN7EXAMPLE",
            secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        )

        self.logger.debug("Cognito auth handler instantiated: %s", self.cognito)

        # Authentication tokens (will be populated during authentication)
        self._token_expiry = None

    def authenticate(self) -> bool:
        """Perform initial authentication and get tokens.

        Returns:
            bool: True if authentication was successful, False otherwise
        """
        try:
            self.logger.debug("Authenticating user: %s, password: %s", self.username, self.password)

            # Handle the async nature of mandate's authenticate method
            self._run_async_cognito(
                self.cognito.authenticate(self.password)
            )

            # Set token expiry (default 1 hour for Cognito)
            self._token_expiry = datetime.now() + timedelta(hours=1)

            self.logger.info("Authentication successful")
            return True

        except Exception as exc:
            self.logger.error("Authentication failed: %r", exc)
            return False

    def _run_async_cognito(self, coroutine):
        """Run an async coroutine in the appropriate context.

        This handles the fact that boto3 (used by mandate) has blocking I/O operations
        that need to be properly managed in both async and sync contexts.

        Args:
            coroutine: The async coroutine to run
        """
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # We're in an async context, use run_coroutine_threadsafe to avoid blocking
                asyncio.run_coroutine_threadsafe(coroutine, loop).result()
            else:
                # We're in a synchronous context, create a new event loop
                asyncio.run(coroutine)
        except RuntimeError:
            # No event loop in this thread
            asyncio.run(coroutine)

    def refresh_auth(self) -> bool:
        """Refresh authentication tokens.

        Tries to use token refresh first, then falls back to re-authentication.

        Returns:
            bool: True if refresh was successful, False otherwise
        """
        # First try to refresh the token (more efficient)
        try:
            self.logger.debug("Attempting to refresh authentication token")

            # Handle the async nature of mandate's token refresh method
            self._run_async_cognito(self.cognito.renew_access_token())

            # Update expiry time
            self._token_expiry = datetime.now() + timedelta(hours=1)

            self.logger.debug("Token refresh successful")
            return True

        except Exception as exc:
            self.logger.warning("Token refresh failed: %r. Falling back to re-authentication.", exc)
            # If token refresh fails, fall back to full re-authentication
            return self.authenticate()

    def ensure_authenticated(self) -> bool:
        """Ensure we have valid tokens, refreshing if needed.

        Returns:
            bool: True if we have valid tokens, False otherwise
        """
        # Check if token exists
        if not hasattr(self.cognito, 'access_token') or not self.cognito.access_token:
            self.logger.debug("Access token doesn't exist - authenticating")
            return self.authenticate()

        # If token is expiring soon, refresh it
        if not self._token_expiry or datetime.now() + timedelta(minutes=5) >= self._token_expiry:
            self.logger.debug("Access token expiring soon - refreshing")
            return self.refresh_auth()

        return True

    @property
    def auth_headers(self) -> Dict[str, str]:
        """Get authorization headers for API requests.

        Returns:
            Dict[str, str]: Headers containing authorization token

        Raises:
            RuntimeError: If unable to obtain valid authentication
        """
        if not self.ensure_authenticated():
            raise RuntimeError("Failed to obtain valid authentication")

        return {
            "Authorization": f"Bearer {self.cognito.id_token}"
        }

    @property
    def ws_auth_params(self) -> Dict[str, Any]:
        """Get authentication parameters for WebSocket connection.

        Returns:
            Dict[str, Any]: Parameters containing authentication token

        Raises:
            RuntimeError: If unable to obtain valid authentication
        """
        if not self.ensure_authenticated():
            raise RuntimeError("Failed to obtain valid authentication")

        return {
            "token": self.cognito.id_token
        }

