"""
Client implementations for MagiqTouch API
"""

import asyncio
import threading
import json
import logging
from typing import Any, Dict, Optional, Union

import requests
import aiohttp

from .auth import CognitoAuth
from .types import UpdateCallback

_LOGGER = logging.getLogger("pymagiqtouch.client")

# MagiqTouch API endpoints - these can be overridden in __init__
DEFAULT_API_URL = "https://tgjgb3bcf3.execute-api.ap-southeast-2.amazonaws.com/prod/v1/"
DEFAULT_WS_URL = "wss://xs5z2412cf.execute-api.ap-southeast-2.amazonaws.com/prod?token="


class MagiqTouchClient:
    """Thread-safe, callback-based WebSocket client for MagiqTouch server."""

    def __init__(
        self,
        username: str,
        password: str,
        update_callback: UpdateCallback,
        ws_url: Optional[str] = None,
        reconnect_delay: float = 5.0,
        heartbeat_interval: float = 60.0,
        logger: Optional[logging.Logger] = None,
    ):
        """Initialize the MagiqTouch WebSocket client.

        Args:
            username: MagiqTouch account username
            password: MagiqTouch account password
            update_callback: Function to call when updates are received
            ws_url: WebSocket URL
            reconnect_delay: Initial delay between reconnection attempts
            heartbeat_interval: Interval between WebSocket heartbeats
            logger: Optional custom logger
        """
        self.connection_ready = threading.Event()
        self.update_callback = update_callback
        self.reconnect_delay = reconnect_delay
        self.heartbeat_interval = heartbeat_interval
        self.logger = logger or _LOGGER

        # Initialize authentication
        self.logger.debug("Initiating Cognito authentication handler")
        self.auth = CognitoAuth(
            username=username,
            password=password,
            logger=self.logger
        )

        self._thread = None
        self._loop = None
        self._stop_event = threading.Event()
        self._ws_url = ws_url or DEFAULT_WS_URL
        self._ws = None
        self._lock = threading.Lock()
        self._keepalive_task = None
        self._retry_attempts = 0
        self._max_retry_delay = 300  # Max 5 minutes between retries

    def start(self):
        """Start the WebSocket client in a background thread."""
        if self._thread and self._thread.is_alive():
            self.logger.debug("WS thread already running, no need to (re)start")
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        self.logger.debug("Started thread: %s", self._thread)

    def stop(self):
        """Stop the WebSocket client and close connection."""
        self._stop_event.set()
        if self._loop:
            asyncio.run_coroutine_threadsafe(self._shutdown(), self._loop)
        if self._thread:
            self._thread.join(timeout=10)

    def send(self, message: Dict[str, Any]):
        """Send a message to the server (JSON dict). Thread-safe.

        Args:
            message: Dictionary to send as JSON

        Raises:
            RuntimeError: If WebSocket is not connected
        """
        if not self._loop or not self._ws:
            raise RuntimeError("WebSocket is not connected.")
        msg = json.dumps(message)
        # aiohttp WebSocket uses send_str, not send
        self.logger.info("Sending string: %s", msg)
        asyncio.run_coroutine_threadsafe(self._ws.send_str(msg), self._loop)

    def send_command(self, command: str, params: Optional[Dict[str, Any]] = None):
        """Send a structured command to the server.

        Args:
            command: Command name/type
            params: Optional parameters for the command
        """
        message = {
            "action": command,
            "params": params or {}
        }
        self.send(message)

    def _run_loop(self):
        """Run the event loop in a background thread."""
        self.logger.debug("Setting up event loop in background thread")
        asyncio.set_event_loop_policy(asyncio.DefaultEventLoopPolicy())
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._loop.run_until_complete(self._run_forever())

    async def _run_forever(self):
        """Run the WebSocket client forever, reconnecting as needed."""
        # Create the aiohttp session if it doesn't exist
        if not hasattr(self, 'httpsession') or self.httpsession is None:
            self.logger.debug("HTTP session doesn't exist - instantiating")
            self.httpsession = aiohttp.ClientSession()

        try:
            while not self._stop_event.is_set():
                try:
                    # Authenticate first if necessary
                    if not await self.auth.ensure_valid_token():
                        self.logger.error("Authentication failed, retrying...")
                        await self._delay_retry()
                        continue

                    await self._connect_and_listen()

                    # If we get here, the connection was closed or failed
                    # Always apply backoff, even for normal disconnects
                    if not self._stop_event.is_set():
                        await self._delay_retry()

                except Exception as exc:
                    self.logger.warning("WebSocket error: %r. Reconnecting after delay.", exc)
                    await self._delay_retry()
        finally:
            # Clean up the session when exiting - this should always happen
            if hasattr(self, 'httpsession') and self.httpsession is not None:
                self.logger.debug("Closing HTTP session in _run_forever finally block")
                await self.httpsession.close()
                self.httpsession = None

    async def _delay_retry(self):
        """Wait before retrying connection, using exponential backoff."""
        delay = min(self.reconnect_delay * (2 ** self._retry_attempts), self._max_retry_delay)
        self._retry_attempts += 1
        self.logger.info("Waiting %.1fs before reconnecting (attempt %d)",
                        delay, self._retry_attempts)

        # Create countdown for nicer logs and to allow clean cancellation
        remaining = delay
        step = 1.0

        while remaining > 0 and not self._stop_event.is_set():
            # Calculate next step (avoid overshooting)
            wait_time = min(step, remaining)
            await asyncio.sleep(wait_time)
            remaining -= wait_time

            # Only log for longer waits and not too frequently
            if delay > 5 and remaining % 5 < step:
                self.logger.debug("Reconnect in %.1fs...", remaining)

    async def _connect_and_listen(self):
        """Connect to the WebSocket and listen for messages using aiohttp."""
        # Get WebSocket URL from auth
        base_url = self._ws_url
        self.connection_ready.clear()

        # Add authentication to the WebSocket URL
        url = self._get_authenticated_ws_url(base_url)

        self.logger.info("Connecting to WebSocket: %s", url)

        # Match the original implementation's headers and parameters
        headers = {
            "user-agent": "Dart/3.2 (dart:io)",
            "sec-websocket-protocol": "wasp"
        }

        heartbeat_task = None

        try:
            # Fix: Check if session exists before using it
            if not hasattr(self, 'httpsession') or self.httpsession is None:
                self.logger.error("No HTTP session available for WebSocket connection")
                return

            async with self.httpsession.ws_connect(
                url,
                headers=headers,
                autoping=False,
                autoclose=True,
            ) as ws:
                self._ws = ws
                self._retry_attempts = 0  # Reset retry counter on successful connection
                self.logger.info("WebSocket connected")

                # Signal that the connection is ready
                self.connection_ready.set()

                # Start authentication keepalive task
                self._keepalive_task = asyncio.create_task(self._auth_keepalive())

                # Start heartbeat task
                heartbeat_task = asyncio.create_task(self._heartbeat(ws))

                # Process incoming messages
                async for msg in ws:
                    # Handle different message types
                    if msg.type == aiohttp.WSMsgType.TEXT:
                        # Process text messages
                        self._handle_message(msg.data)

                    elif msg.type in (
                        aiohttp.WSMsgType.CLOSE,
                        aiohttp.WSMsgType.CLOSING,
                        aiohttp.WSMsgType.CLOSED
                    ):
                        self.logger.info("WebSocket closing: %s", msg.data)
                        break

                    elif msg.type in (aiohttp.WSMsgType.PING, aiohttp.WSMsgType.PONG):
                        self.logger.debug("Ping/Pong: %s", msg.type)

                    elif msg.type == aiohttp.WSMsgType.ERROR:
                        self.logger.warning("WebSocket error: %s", msg)
                        break
                    else:
                        self.logger.warning("Unexpected WebSocket message: %s", msg)

                    # Check if we need to refresh the token
                    if self.auth.is_token_expired():
                        self.logger.info("Token expired, reconnecting")
                        break

                    if self._stop_event.is_set():
                        break

        except aiohttp.ClientConnectionError as exc:
            self.logger.warning("WebSocket connection error: %s", exc)
        except asyncio.CancelledError:
            self.logger.info("WebSocket connection cancelled")
            raise
        except Exception as exc:
            self.logger.error("Connection failed: %r", exc)
        finally:
            # Clear the connection_ready event when disconnected
            self.connection_ready.clear()

            # Kill off keepalive
            if self._keepalive_task:
                self._keepalive_task.cancel()
                self._keepalive_task = None

            if heartbeat_task:
                heartbeat_task.cancel()

            with self._lock:
                self._ws = None

    def _get_authenticated_ws_url(self, base_url: str) -> str:
        """Add authentication to WebSocket URL.

        Args:
            base_url: Base WebSocket URL

        Returns:
            str: WebSocket URL with authentication token
        """
        # Get token directly from auth
        token = self.auth.get_id_token()
        if not token:
            self.logger.error("No ID token available for WebSocket connection")
            raise RuntimeError("No authentication token available")

        # Convert https:// to wss:// (secure websocket) or http:// to ws://
        if base_url.startswith('https://'):
            base_url = 'wss://' + base_url[8:]
        elif base_url.startswith('http://'):
            base_url = 'ws://' + base_url[7:]

        # Simply append the token to the URL as in the original implementation
        authenticated_url = base_url + token
        self.logger.debug("WebSocket URL with token: %s", authenticated_url[:120] + "...")
        return authenticated_url

    async def _shutdown(self):
        """Shut down the WebSocket connection cleanly."""
        if self._keepalive_task:
            self._keepalive_task.cancel()
        if self._ws:
            await self._ws.close()
        if hasattr(self, 'httpsession') and self.httpsession is not None:
            await self.httpsession.close()
            self.httpsession = None

    def _handle_message(self, message: Union[str, bytes, bytearray, memoryview]):
        """Handle a message received from the WebSocket.

        Args:
            message: Message from server (may be str, bytes, bytearray, or memoryview)
        """
        # Convert message to string if it's not already
        if isinstance(message, str):
            message_str = message
        elif isinstance(message, (bytes, bytearray)):
            try:
                message_str = message.decode('utf-8')
            except UnicodeDecodeError as exc:
                self.logger.error("Failed to decode message as UTF-8: %r", exc)
                return
        elif isinstance(message, memoryview):
            # For memoryview, convert to bytes first
            try:
                message_str = bytes(message).decode('utf-8')
            except UnicodeDecodeError as exc:
                self.logger.error("Failed to decode memoryview message as UTF-8: %r", exc)
                return
        else:
            self.logger.error("Unsupported message type: %r", type(message))
            return

        try:
            data = json.loads(message_str)
        except Exception as exc:
            self.logger.error("Invalid JSON from server: %r", exc)
            return

        # Check for error messages
        if isinstance(data, dict) and data.get("error"):
            self.logger.error("Server error: %s", data["error"])
            # Handle authentication errors
            if data.get("code") == "AUTH_EXPIRED" and self._loop is not None:
                asyncio.run_coroutine_threadsafe(self._reconnect_with_fresh_auth(), self._loop)
            return

        try:
            self.update_callback(data)
        except Exception as exc:
            self.logger.error("Error in update callback: %r", exc)

    async def _auth_keepalive(self):
        """Task to keep the authentication alive."""
        while True:
            try:
                await asyncio.sleep(600)  # Check every 10 minutes
                self.logger.debug("Performing auth keepalive check")
                if not await self.auth.ensure_valid_token():
                    self.logger.warning("Auth token refresh failed, reconnecting...")
                    await self._reconnect_with_fresh_auth()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                self.logger.error("Auth keepalive error: %r", exc)
                await asyncio.sleep(60)  # Retry after a minute on error

    async def _reconnect_with_fresh_auth(self):
        """Force reconnection with fresh authentication."""
        if self._ws:
            await self._ws.close()

    async def _heartbeat(self, ws):
        """Send regular heartbeats to keep the connection alive.

        Args:
            ws: WebSocket connection
        """
        while True:
            try:
                # Send ping - aiohttp uses ping() method
                await ws.ping()

            except Exception as exc:
                self.logger.warning("Heartbeat failed: %r", exc)
                break
            await asyncio.sleep(self.heartbeat_interval)

    @property
    def ws_endpoint(self) -> str:
        """Get the WebSocket endpoint.

        Returns:
            str: WebSocket endpoint URL
        """
        return self._ws_url


# REST Client implementation
class MagiqTouchRestClient:
    """REST API wrapper for MagiqTouch server with authentication."""

    def __init__(
        self,
        username: str,
        password: str,
        base_url: Optional[str] = None,
        api_url: Optional[str] = None,
        timeout: float = 10.0,
        logger: Optional[logging.Logger] = None
    ):
        """Initialize the MagiqTouch REST API client.

        Args:
            username: MagiqTouch account username
            password: MagiqTouch account password
            base_url: Base REST API URL
            timeout: Request timeout in seconds
            logger: Optional custom logger
        """
        self.timeout = timeout
        self.logger = logger or _LOGGER
        self.session = requests.Session()

        # Use provided URLs or defaults
        self._api_url = api_url or DEFAULT_API_URL

        # Initialize authentication
        self.auth = CognitoAuth(
            username=username,
            password=password,
            logger=self.logger
        )

    def get(self, path: str, **kwargs) -> Any:
        """Make an authenticated GET request.

        Args:
            path: API path to request
            **kwargs: Additional arguments for requests.get

        Returns:
            Any: Parsed JSON response

        Raises:
            RuntimeError: If authentication fails
            requests.HTTPError: If the request fails
        """
        base_url = self._api_url
        url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"

        # Ensure we have valid authentication
        if not self.auth.ensure_authenticated():
            raise RuntimeError("Authentication failed")

        # Add auth headers
        headers = kwargs.pop("headers", {})
        headers.update(self.auth.auth_headers)

        try:
            resp = self.session.get(url, headers=headers, timeout=self.timeout, **kwargs)
            resp.raise_for_status()
            return resp.json()
        except requests.HTTPError as exc:
            if exc.response.status_code in (401, 403):
                self.logger.error("Authentication expired during request, refreshing...")
                if self.auth.authenticate():  # Force full re-auth
                    # Retry once with new auth
                    headers.update(self.auth.auth_headers)
                    resp = self.session.get(url, headers=headers, timeout=self.timeout, **kwargs)
                    resp.raise_for_status()
                    return resp.json()
            self.logger.error("REST GET %s failed: %r", url, exc)
            raise
        except Exception as exc:
            self.logger.error("REST GET %s failed: %r", url, exc)
            raise

    def post(self, path: str, data: Any = None, **kwargs) -> Any:
        """Make an authenticated POST request.

        Args:
            path: API path to request
            data: JSON data to send
            **kwargs: Additional arguments for requests.post

        Returns:
            Any: Parsed JSON response

        Raises:
            RuntimeError: If authentication fails
            requests.HTTPError: If the request fails
        """
        base_url = self._api_url
        url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"

        # Ensure we have valid authentication
        if not self.auth.ensure_authenticated():
            raise RuntimeError("Authentication failed")

        # Add auth headers
        headers = kwargs.pop("headers", {})
        headers.update(self.auth.auth_headers)

        try:
            resp = self.session.post(url, json=data, headers=headers, timeout=self.timeout, **kwargs)
            resp.raise_for_status()
            return resp.json()
        except requests.HTTPError as exc:
            if exc.response.status_code in (401, 403):
                self.logger.error("Authentication expired during request, refreshing...")
                if self.auth.authenticate():  # Force full re-auth
                    # Retry once with new auth
                    headers.update(self.auth.auth_headers)
                    resp = self.session.post(url, json=data, headers=headers,
                                           timeout=self.timeout, **kwargs)
                    resp.raise_for_status()
                    return resp.json()
            self.logger.error("REST POST %s failed: %r", url, exc)
            raise
        except Exception as exc:
            self.logger.error("REST POST %s failed: %r", url, exc)
            raise

    def close(self):
        """Close the session."""
        self.session.close()

    @property
    def rest_endpoint(self) -> str:
        """Get the REST API endpoint.

        Returns:
            str: REST API endpoint URL
        """
        return self._api_url

