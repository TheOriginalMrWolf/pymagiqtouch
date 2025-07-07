#!/usr/bin/env python3
"""
Test script for MagiqTouch authentication
"""

import argparse
import logging
import sys
import json
from typing import Dict, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("auth_test")

# Set debug logging for urllib3
logging.getLogger("urllib3").setLevel(logging.INFO)

def main():
    parser = argparse.ArgumentParser(description="Test MagiqTouch authentication")
    parser.add_argument("username", help="MagiqTouch username")
    parser.add_argument("password", help="MagiqTouch password")
    args = parser.parse_args()

    # Import here to make sure logging is configured first
    from pymagiqtouch.auth import CognitoAuth

    # Create auth client
    auth = CognitoAuth(
        username=args.username,
        password=args.password,
        logger=logger
    )

    # Test authentication
    logger.info("Testing authentication...")
    result = auth.authenticate()

    if result:
        logger.info("✅ Authentication successful!")
        logger.info("ID Token: %s...", auth.cognito.id_token[:20] if auth.cognito.id_token else "None")
        logger.info("Token expiry: %s", auth._token_expiry)

        # Test generating auth headers
        logger.info("Auth headers: %s", auth.auth_headers)

        # Test WebSocket params
        logger.info("WebSocket auth params: %s", auth.ws_auth_params)

        # Show endpoints
        logger.info("REST endpoint: %s", auth.rest_endpoint)
        logger.info("WebSocket endpoint: %s", auth.ws_endpoint)

        return 0
    else:
        logger.error("❌ Authentication failed!")
        return 1

if __name__ == "__main__":
    sys.exit(main())
