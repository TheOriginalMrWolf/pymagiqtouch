"""
Command-line interface for PyMagiqTouch
"""

import argparse
import logging
import sys
import time

from .client import MagiqTouchClient, MagiqTouchRestClient

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
_LOGGER = logging.getLogger("pymagiqtouch")

EXAMPLE_ZONES = {
    "Living Room": {"heater": {}, "cooler": {}, "foo": "bar"},
    "Master": {"heater": {}, "cooler": {}, "baz": 123}
}


def print_update(data):
    """Callback to print WebSocket updates."""
    print("[WS UPDATE]", data)


def test_ws(username, password, ws_url=None, use_discovery=False, duration=30):
    """Test the WebSocket interface.

    Args:
        username: MagiqTouch username
        password: MagiqTouch password
        ws_url: Optional WebSocket URL override
        use_discovery: Whether to use endpoint discovery
        duration: How long to run the test in seconds
    """
    _LOGGER.info("Testing WebSocket interface for %ss...", duration)
    client = MagiqTouchClient(
        username=username,
        password=password,
        ws_url=ws_url,
        use_discovery=use_discovery,
        zones_lookup=EXAMPLE_ZONES,
        update_callback=print_update,
    )
    client.start()
    try:
        time.sleep(duration)
    except KeyboardInterrupt:
        pass
    finally:
        client.stop()
    _LOGGER.info("WebSocket test finished.")


def test_rest(username, password, base_url=None, use_discovery=False):
    """Test the REST API.

    Args:
        username: MagiqTouch username
        password: MagiqTouch password
        base_url: Optional REST API URL override
        use_discovery: Whether to use endpoint discovery
    """
    _LOGGER.info("Testing REST API...")
    rest = MagiqTouchRestClient(
        username=username,
        password=password,
        base_url=base_url,
        use_discovery=use_discovery
    )
    try:
        # Try to get device info
        resp = rest.get("/devices")
        print("[DEVICES]", resp)

        # Get system status
        resp = rest.get("/status")
        print("[STATUS]", resp)
    except Exception as exc:
        print("REST API test failed:", exc)
    finally:
        rest.close()


def main():
    """Main entry point for CLI."""
    parser = argparse.ArgumentParser(
        description="PyMagiqTouch - MagiqTouch Server API tester"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Common auth arguments
    auth_args = argparse.ArgumentParser(add_help=False)
    auth_args.add_argument("--username", "-u", required=True,
                         help="MagiqTouch username")
    auth_args.add_argument("--password", "-p", required=True,
                         help="MagiqTouch password")
    auth_args.add_argument("--discovery", "-d", action="store_true",
                         help="Use endpoint discovery")

    # WebSocket test command
    ws_parser = subparsers.add_parser(
        "test-ws",
        help="Test WebSocket interface",
        parents=[auth_args]
    )
    ws_parser.add_argument("--url", help="WebSocket URL override")
    ws_parser.add_argument("--duration", type=int, default=30,
                         help="Seconds to run test")

    # REST API test command
    rest_parser = subparsers.add_parser(
        "test-rest",
        help="Test REST API",
        parents=[auth_args]
    )
    rest_parser.add_argument("--url", help="REST API URL override")

    args = parser.parse_args()

    if args.command == "test-ws":
        test_ws(
            username=args.username,
            password=args.password,
            ws_url=args.url,
            use_discovery=args.discovery,
            duration=args.duration
        )
    elif args.command == "test-rest":
        test_rest(
            username=args.username,
            password=args.password,
            base_url=args.url,
            use_discovery=args.discovery
        )
    else:
        parser.print_help()


if __name__ == "__main__":
    main()