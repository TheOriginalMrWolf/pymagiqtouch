# PyMagiqTouch

Python client library for Seeley MagiQtouch heating and cooling units, with a focus on Home Assistant integration.

## Features

- Thread-safe, callback-based WebSocket client with automatic reconnection
- REST API client
- Pass-through of original JSON structures with zones information
- Robust error handling
- CLI for testing both REST and WebSocket APIs

## Installation

```bash
# From PyPI (once published)
pip install pymagiqtouch

# From local directory
pip install .
```

## Usage

### WebSocket Client

```python
from pymagiqtouch import MagiqTouchClient

def handle_update(data):
    print(f"Received update: {data}")
    # Process data here...

# Define your zones
zones = {
    "Living Room": {"heater": {}, "cooler": {}}
}

client = MagiqTouchClient(
    username="your_username",
    password="your_password",
    zones_lookup=zones,  # Can also be a function returning zones
    update_callback=handle_update
)

# Start the client
client.start()

# Send a command
client.send_command("set_mode", {"device": "living_room", "mode": "cool"})

# Later, stop the client
client.stop()
```

### REST Client

```python
from pymagiqtouch import MagiqTouchRestClient

client = MagiqTouchRestClient(
    username="your_username",
    password="your_password"
)

# Get devices
devices = client.get("/devices")
print(devices)

# Get status
status = client.get("/status")
print(status)

# Send a command
result = client.post("/command", {
    "command": "set_temperature",
    "parameters": {
        "device": "living_room",
        "temperature": 22
    }
})

# Close the client when done
client.close()
```

## Command Line Interface

Test the WebSocket interface:
```bash
magiqtouch test-ws -u your_username -p your_password --duration 60
```

Test the REST API:
```bash
magiqtouch test-rest -u your_username -p your_password
```

## Home Assistant Integration

This library is designed to work well with Home Assistant integrations:

```python
from homeassistant.core import HomeAssistant
from pymagiqtouch import MagiqTouchClient

class MagiqTouchIntegration:
    def __init__(self, hass: HomeAssistant, username: str, password: str):
        self.hass = hass

        # Create client with callback to update Home Assistant
        self.client = MagiqTouchClient(
            username=username,
            password=password,
            zones_lookup=self.get_zones,
            update_callback=self.handle_update
        )

    def get_zones(self):
        # Return zones structure
        return {...}

    def handle_update(self, data):
        # This callback will be called for each update
        # Schedule state updates in Home Assistant
        self.hass.async_create_task(self.async_update_ha_state(data))

    async def async_update_ha_state(self, data):
        # Update HA states based on data
        pass
```