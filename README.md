# micropython-p115

This project is a MicroPython library for interacting with the Tapo P115 smart plug. It provides a simple interface to control the plug, including turning it on and off, toggling its state, and retrieving device information.

## Features

- Control Tapo P115 smart plug
- Get device information and name
- Implement Klap two handshake authentication for secure communication

## Installation

To install the micropython-p115 library, copy the p115.py file to your MicroPython environment.

Alternatively, mip can be used to install the module on your device.  
This approach requires an active network connection.

```bash
import mip
mip.install("github:ericmvaughn/micropython-p115/p115.py")
```

## Usage

Here is a basic example of how to use the P115 class:

```python
from p115 import P115

# Initialize the P115 class with the device's IP address and credentials
plug = P115("192.168.1.100", "username", "password")

# Turn on the plug
plug.turn_on()

# Get plug information
info = plug.get_device_info()
print(info)

# Turn off the plug
plug.turn_off()

# Toggle the plug state
plug.toggle()

# Turn on/off with a delay
plug.switch_with_delay(True, 60)
```

## List of commands
- turn_on
- turn_off
- get_device_info
- get_device_name
- toggle
- switch_with_delay
- stop_countdown
- get_countdown_rules
- set_state
- get_state

## Debugging
The logging level can be increase to display more details of the interactions
between the app and the plug.  This is done by providing one of the standing
logging levels when creating the plug class.

```bash
plug = P115("192.168.1.100", "username", "password", "DEBUG")
```
possible values
```
CRITICAL
FATAL
ERROR
WARNING  (defualt)
WARN
INFO
DEBUG
NOTSET

```

## Authentication

Tapo P115 smartplug uses the Klap V2 protocol to authenticate the connections.

auth_hash = sha256(sha1(username) + sha1(password))

Handshake1:  The client sends the plug it's local seed (random 16 bytes) and the plug returns 
its remote seed in the first 16 bytes followed by the sha256 hash of the remote_seed, local_seed, 
and auth_hash.

handshake1_seed_auth_hash = sha256(local_seed + remote_seed + auth_hash)

The handshake1_seed_auth_hash is calculated locally and compared to what the plug returned before proceeding.

Then the following value is sent to the plug to verify the app knows the correct username and password (auth_hash).

handshake2_seed_auth_hash = sha256(remote_seed + local_seed + auth_hash)

Once the handshake is complete the local_seed, remote_seed, and auth_hash are used to
encrypt/decrypt the packets.

## Code formatting
Ruff is used to verify and optionally fix the code formatting issues.

#### Example commands
```
# check commands
ruff check p115.py
ruff format --diff p115.py

# fix commands
ruff check --fix p115.py
ruff format p115.py
```

## Acknowledgements

The following projects have been used for reference and inspiration for this effort.

- https://github.com/python-kasa/python-kasa
- https://github.com/ikakunsan/tplink-hs105
- https://github.com/fishbigger/TapoP100
- https://github.com/almottier/TapoP100
- https://github.com/iyassou/mpyaes
- https://gitlab.com/0xSamy/TapoPlug-Rest-API


## License

This project is licensed under the MIT License. See the LICENSE file for more details.