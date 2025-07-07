#!/usr/bin/env python3
"""
Test script for MagiqTouch WebSocket client
"""

import argparse
import sys
import time
import logging
import json
from datetime import datetime, timedelta

from pymagiqtouch.client import MagiqTouchClient

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler()]
)

_LOGGER = logging.getLogger("ws_test")

# Keep track of received messages
received_messages = []

def update_callback(data):
    """Callback function for WebSocket updates."""
    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    _LOGGER.info("[%s] Received update: %s", timestamp, json.dumps(data)[:120] + "...")
    received_messages.append(data)

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Test MagiqTouch WebSocket client")
    parser.add_argument("username", help="MagiqTouch account username")
    parser.add_argument("password", help="MagiqTouch account password")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--duration", type=int, default=60,
                        help="Duration to keep the WebSocket open (seconds)")
    parser.add_argument("--send-status", type=str, default=None,
                        help="Send status request for device ID (e.g., '90E202CADD0C')")
    parser.add_argument("--heartbeat", type=int, default=30,
                        help="Heartbeat interval in seconds")
    parser.add_argument("--connection-timeout", type=int, default=10,
                        help="Timeout for waiting for WebSocket connection (seconds)")
    return parser.parse_args()

def main():
    """Run the WebSocket test."""
    args = parse_args()

    # Set debug logging if requested
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        # Initialize the WebSocket client
        client = MagiqTouchClient(
            username=args.username,
            password=args.password,
            update_callback=update_callback,
            reconnect_delay=2.0,
            heartbeat_interval=args.heartbeat
        )

        # # First, authenticate manually to ensure it works
        # if not client.auth.authenticate():
        #     _LOGGER.error("❌ Authentication failed!")
        #     return 1

        # _LOGGER.info("✅ Authentication successful")
        _LOGGER.info("WebSocket endpoint: %s", client.ws_endpoint)

        # Start the WebSocket client
        _LOGGER.info("Starting WebSocket client...")
        client.start()

        # Wait for the WebSocket connection to be ready
        _LOGGER.info(f"Waiting up to {args.connection_timeout} seconds for connection...")
        if client.connection_ready.wait(timeout=args.connection_timeout):
            _LOGGER.info("✅ WebSocket connection established")
        else:
            _LOGGER.warning("⚠️ Timed out waiting for WebSocket connection")

        # Send a status request if specified
        if args.send_status:
            try:
                server_command = {"action": "status", "params": {"device": args.send_status}}
                client.send(server_command)
                _LOGGER.info("Sent status request for device: %s", args.send_status)
            except Exception as exc:
                _LOGGER.error("Failed to send command: %r", exc)

        # Calculate end time
        end_time = datetime.now() + timedelta(seconds=args.duration)
        _LOGGER.info("Keeping WebSocket open for %d seconds (until %s)...",
                     args.duration, end_time.strftime("%H:%M:%S"))

        # Main loop - keep running until duration expires
        try:
            while datetime.now() < end_time:
                remaining = (end_time - datetime.now()).total_seconds()
                if remaining <= 0:
                    break

                # Sleep in small intervals to respond to keyboard interrupts
                sleep_time = min(1.0, remaining)
                time.sleep(sleep_time)

                # Every 15 seconds, show how many messages we've received
                if int(remaining) % 15 == 0 and int(remaining) != int(remaining + sleep_time):
                    _LOGGER.info("[%s] Received %d message(s) so far, %d seconds remaining", datetime.now().strftime("%H:%M:%S.%f")[:-3],
                                len(received_messages), int(remaining))

        except KeyboardInterrupt:
            _LOGGER.info("Test interrupted by user")

        # Stop the WebSocket client
        _LOGGER.info("Stopping WebSocket client...")
        client.stop()

        _LOGGER.info("Test completed. Received %d total messages", len(received_messages))
        return 0

    except Exception as exc:
        _LOGGER.error("Test failed with error: %r", exc)
        return 1

if __name__ == "__main__":
    sys.exit(main())