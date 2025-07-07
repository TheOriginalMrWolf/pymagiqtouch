"""
Authentication handling for MagiqTouch API
"""

import asyncio
import logging
import json
import base64
from datetime import datetime, timedelta
from typing import Dict, Any, Optional

from mandate import Cognito
from mandate.exceptions import TokenVerificationException

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
        # Note: attrs-based class constructor confuses linters
        cognito_config = {
            "user_pool_id": self.AWS_USER_POOL_ID,
            "client_id": self.CLIENT_ID,
            "user_pool_region": self.COGNITO_REGION,
            "username": self.username,
            # Dummy credentials to bypass EC2 IMDS
            "access_key": "AKIAIOSFODNN7EXAMPLE",
            "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        }
        self.cognito = Cognito(**cognito_config)

        self.logger.debug("Cognito auth handler instantiated: %s", self.cognito)

        # Authentication tokens (will be populated during authentication)
        self._access_token_expiry = None
        self._refresh_token_expiry = None
        self._last_auth_time = None

    # === MAIN ASYNC METHODS ===
    async def authenticate_async(self) -> bool:
        """Perform initial authentication and get tokens."""
        try:
            self.logger.debug("Authenticating user: %s", self.username)

            # The cognito.authenticate method is async, so we need to await it directly
            await self.cognito.authenticate(self.password)

            # Debug: Check what tokens we received
            access_token = self.get_access_token()
            id_token = self.get_id_token()
            refresh_token = self.get_refresh_token()

            self.logger.debug("Tokens received - Access: %s, ID: %s, Refresh: %s", bool(access_token), bool(id_token), bool(refresh_token))

            # Debug: Check refresh token type
            refresh_token_encrypted = False
            if refresh_token:
                if refresh_token.startswith('eyJ') and len(refresh_token.split('.')) == 5:
                    self.logger.debug("Refresh token is encrypted (JWE) - cannot decode expiry")
                    refresh_token_encrypted = True
                else:
                    self.logger.debug("Refresh token is JWT - can decode expiry")

            # Debug: show token information
            access_payload = self._decode_jwt_payload(access_token) if access_token else None
            id_payload = self._decode_jwt_payload(id_token) if id_token else None
            refresh_payload = self._decode_jwt_payload(refresh_token) if refresh_token and not refresh_token_encrypted else None

            self.logger.debug("Access token payload: %s", {k: v for k, v in (access_payload or {}).items() if k in ['exp', 'iat', 'token_use', 'client_id']})
            self.logger.debug("ID token payload: %s", {k: v for k, v in (id_payload or {}).items() if k in ['exp', 'iat', 'token_use', 'client_id']})
            self.logger.debug("Refresh token payload: %s", {k: v for k, v in (refresh_payload or {}).items() if k in ['exp', 'iat', 'token_use', 'client_id']})

            # Set token expiry times
            self._update_token_expiry()
            self._last_auth_time = datetime.now()

            self.logger.info("Authentication successful")
            return True

        except Exception as exc:
            self.logger.error("Authentication failed: %r", exc)
            return False

    async def refresh_tokens_async(self) -> bool:
        """Refresh tokens using the refresh token."""
        if not self.cognito:
            self.logger.warning("No Cognito client available for token refresh")
            return await self.authenticate_async()

        try:
            self.logger.debug("Refreshing tokens for user: %s", self.username)

            await self.cognito.renew_access_token()

            # Update token expiry
            self._update_token_expiry()

            self.logger.info("Token refresh successful")
            return True

        except TokenVerificationException as exc:
            self.logger.warning("Token refresh failed, attempting full re-authentication: %r", exc)
            return await self.authenticate_async()
        except Exception as exc:
            self.logger.error("Token refresh failed: %r", exc)
            return False

    async def ensure_valid_token(self) -> bool:
        """Ensure we have a valid access token, refreshing if necessary."""
        # Check if token exists
        if not hasattr(self.cognito, 'access_token') or not self.cognito.access_token:
            self.logger.debug("Access token doesn't exist - authenticating")
            result = await self.authenticate_async()
            if result:
                self.logger.debug("Authentication completed. ID token exists: %s",
                                bool(self.get_id_token()))
            return result

        # If token is expired/expiring soon, refresh it
        if self.is_token_expired():
            if self.is_refresh_token_expired():
                self.logger.info("Refresh token expired, performing full re-authentication")
                return await self.authenticate_async()
            else:
                self.logger.info("Access token expired, refreshing tokens")
                return await self.refresh_tokens_async()

        return True

    # === SYNC WRAPPERS (for REST client compatibility) ===
    def authenticate(self) -> bool:
        """Synchronous authentication wrapper for REST client."""
        try:
            return asyncio.run(self.authenticate_async())
        except Exception as exc:
            self.logger.error("Sync authentication failed: %r", exc)
            return False

    def ensure_authenticated(self) -> bool:
        """Synchronous token validation wrapper for REST client."""
        try:
            return asyncio.run(self.ensure_valid_token())
        except Exception as exc:
            self.logger.error("Sync token validation failed: %r", exc)
            return False

    # === HELPER METHODS ===
    async def _run_blocking_operation(self, func, *args, **kwargs):
        """Run a blocking operation in a thread pool to avoid blocking the event loop."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, func, *args, **kwargs)

    def _update_token_expiry(self):
        """Update token expiry times based on actual token expiration claims."""
        now = datetime.now()

        # Get access token expiry from the token itself
        access_token = self.get_access_token()
        if access_token:
            payload = self._decode_jwt_payload(access_token)
            if payload and 'exp' in payload:
                # JWT exp is in seconds since epoch
                self._access_token_expiry = datetime.fromtimestamp(payload['exp'])
                self.logger.debug("Access token expires at: %s", self._access_token_expiry)
            else:
                # Fallback to default if we can't parse the token
                self._access_token_expiry = now + timedelta(hours=1)
                self.logger.warning("Could not parse access token expiry, using default 1 hour")
        else:
            self._access_token_expiry = None
            self.logger.warning("No access token available for expiry calculation")

        # Handle refresh token expiry
        refresh_token = self.get_refresh_token()
        if refresh_token:
            # Check if it's a JWE token (encrypted) - these start with eyJ and have 5 parts
            if refresh_token.startswith('eyJ') and len(refresh_token.split('.')) == 5:
                # This is a JWE (encrypted) token - we can't decode it
                # Use AWS Cognito's default refresh token lifetime (30 days)
                self._refresh_token_expiry = now + timedelta(days=30)
                self.logger.debug("Refresh token is encrypted (JWE), using default 30 days expiry")
            else:
                # Try to decode as JWT
                payload = self._decode_jwt_payload(refresh_token)
                if payload and 'exp' in payload:
                    self._refresh_token_expiry = datetime.fromtimestamp(payload['exp'])
                    self.logger.debug("Refresh token expires at: %s", self._refresh_token_expiry)
                else:
                    # Fallback to default
                    self._refresh_token_expiry = now + timedelta(days=30)
                    self.logger.warning("Could not parse refresh token expiry, using default 30 days")
        else:
            # If no refresh token, assume it expires in 30 days
            self._refresh_token_expiry = now + timedelta(days=30)
            self.logger.debug("No refresh token available, using default 30 days")



    def _decode_jwt_payload(self, token: str) -> Optional[Dict[str, Any]]:
        """Decode JWT payload to extract claims like expiration time."""
        try:
            # JWT tokens have 3 parts separated by dots: header.payload.signature
            # We only need the payload (middle part)
            parts = token.split('.')
            if len(parts) != 3:
                return None

            # Add padding if necessary (base64 requires padding)
            payload = parts[1]
            padding = len(payload) % 4
            if padding:
                payload += '=' * (4 - padding)

            # Decode the base64 payload
            decoded = base64.urlsafe_b64decode(payload)
            decoded_jwt_as_json = json.loads(decoded)
            self.logger.debug("Decoded JWT payload: %s", json.dumps(decoded_jwt_as_json))
            return decoded_jwt_as_json

        except Exception as exc:
            self.logger.warning("Failed to decode JWT token: %r", exc)
            return None

    def is_token_expired(self) -> bool:
        """Check if the access token is expired or about to expire."""
        if not self._access_token_expiry:
            return True

        # Consider token expired if it expires within the next 5 minutes
        buffer_time = timedelta(minutes=5)
        expires_soon = datetime.now() + buffer_time >= self._access_token_expiry

        if expires_soon:
            self.logger.debug("Access token expires soon at %s, considering expired", self._access_token_expiry)

        return expires_soon


    def is_refresh_token_expired(self) -> bool:
        """Check if the refresh token is expired."""
        if not self._refresh_token_expiry:
            return True

        expired = datetime.now() >= self._refresh_token_expiry

        if expired:
            self.logger.debug("Refresh token expired at %s", self._refresh_token_expiry)

        return expired


    # === TOKEN ACCESS METHODS ===
    def get_access_token(self) -> Optional[str]:
        """Get the current access token."""
        if self.cognito and hasattr(self.cognito, 'access_token') and self.cognito.access_token:
            return self.cognito.access_token
        return None

    def get_id_token(self) -> Optional[str]:
        """Get the current ID token."""
        if self.cognito and hasattr(self.cognito, 'id_token') and self.cognito.id_token:
            return self.cognito.id_token
        return None

    def get_refresh_token(self) -> Optional[str]:
        """Get the current refresh token."""
        if self.cognito and hasattr(self.cognito, 'refresh_token') and self.cognito.refresh_token:
            return self.cognito.refresh_token
        return None

    def get_token_status(self) -> Dict[str, Any]:
        """Get current token status for debugging."""
        now = datetime.now()

        status = {
            'authenticated': bool(self.get_access_token()),
            'access_token_available': bool(self.get_access_token()),
            'id_token_available': bool(self.get_id_token()),
            'refresh_token_available': bool(self.get_refresh_token()),
            'access_token_expiry': self._access_token_expiry,
            'refresh_token_expiry': self._refresh_token_expiry,
            'last_auth_time': self._last_auth_time,
            }

        if self._access_token_expiry:
            status['access_token_expires_in'] = (self._access_token_expiry - now).total_seconds()
            status['access_token_expired'] = self.is_token_expired()

        if self._refresh_token_expiry:
            status['refresh_token_expires_in'] = (self._refresh_token_expiry - now).total_seconds()
            status['refresh_token_expired'] = self.is_refresh_token_expired()

        return status

    # === CONVENIENCE PROPERTIES (for REST client compatibility) ===
    @property
    def auth_headers(self) -> Dict[str, str]:
        """Get authorization headers for API requests."""
        id_token = self.get_id_token()
        if not id_token:
            raise RuntimeError("No valid authentication token available")

        return {
            "Authorization": f"Bearer {id_token}"
        }
