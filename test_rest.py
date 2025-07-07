#!/usr/bin/env python3
"""
Test script for PyMagiqTouch REST API client with debug logging
"""

import argparse
import logging
import sys
import json
from typing import Dict, Any, Optional

from pymagiqtouch import MagiqTouchRestClient

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("pymagiqtouch_test")

# Set debug logging for all pymagiqtouch components
logging.getLogger("pymagiqtouch").setLevel(logging.INFO)
logging.getLogger("pymagiqtouch.auth").setLevel(logging.INFO)
logging.getLogger("pymagiqtouch.client").setLevel(logging.INFO)

def pretty_print_json(data: Dict[str, Any]) -> None:
    """Print JSON data in a pretty format"""
    print(json.dumps(data, indent=2, sort_keys=True))

def test_rest_api(username: str, password: str, base_url: Optional[str] = None) -> None:
    """Test MagiqTouch REST API functionality

    Args:
        username: MagiqTouch username
        password: MagiqTouch password
        base_url: Optional REST API base URL
    """
    logger.info("Creating MagiqTouchRestClient")
    client = MagiqTouchRestClient(
        username=username,
        password=password,
        base_url=base_url,
        logger=logger
    )

    try:
        logger.info("Authenticating and testing connection...")

        # Test basic endpoints
        endpoints = [
            "devices/system"
        ]

        for endpoint in endpoints:
            try:
                logger.info(f"Requesting /{endpoint}")
                data = client.get(endpoint)
                logger.info(f"Success! Response from /{endpoint}:")
                pretty_print_json(data)
            except Exception as exc:
                logger.error(f"Failed to get /{endpoint}: {exc}")

        # Try a more specific endpoint if available
        try:
            device_id = input("\nOptional: Enter a device ID to get details (or press Enter to skip): ").strip()
            if device_id:
                logger.info(f"Requesting /device/{device_id}")
                data = client.get(f"device/{device_id}")
                logger.info(f"Success! Device details:")
                pretty_print_json(data)
        except Exception as exc:
            logger.error(f"Failed to get device details: {exc}")

    except Exception as exc:
        logger.error(f"Test failed with error: {exc}")
    finally:
        client.close()
        logger.info("Test completed")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test PyMagiqTouch REST API")
    parser.add_argument("username", help="MagiqTouch username")
    parser.add_argument("password", help="MagiqTouch password")
    parser.add_argument("--url", help="Optional REST API base URL")

    args = parser.parse_args()

    test_rest_api(args.username, args.password, args.url)