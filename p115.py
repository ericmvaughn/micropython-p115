import json
import binascii
from os import urandom
from hashlib import sha256 as hashlib_sha256
from hashlib import sha1 as hashlib_sha1
import requests
import cryptolib
import struct
import logging

SESSION_COOKIE_NAME = "TP_SESSIONID"
TIMEOUT_COOKIE_NAME = "TIMEOUT"
HANDSHAKE1 = "handshake1"
HANDSHAKE2 = "handshake2"
REQUEST_PATH = "request"

log_level_dict = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
}

logging.basicConfig(level=logging.DEBUG)
log: logging.Logger = logging.getLogger(__name__)


class CryptoUtils:
    @staticmethod
    def generate_random_bytes(length: int) -> bytes:
        return urandom(length)

    @staticmethod
    def sha256(data: bytes) -> bytes:
        h = hashlib_sha256()
        h.update(data)
        return h.digest()

    @staticmethod
    def sha1(data: bytes) -> bytes:
        h = hashlib_sha1()
        h.update(data)
        return h.digest()

    @staticmethod
    def pack_long(value: int) -> bytes:
        return struct.pack(">l", value)

    @staticmethod
    def generate_seed() -> bytes:
        return urandom(16)


class PKCS7:
    @staticmethod
    def pad(plaintext: bytearray | bytes | str, block_size: int) -> None:
        # Pads a block. Makes use of bytearray.extend.
        if block_size <= 0:
            raise ValueError("block size must be greater than 0")
        if not isinstance(plaintext, bytearray):
            if isinstance(plaintext, str):
                plaintext = bytearray(plaintext, "utf-8")
            else:
                plaintext = bytearray(plaintext)
        padval = block_size - (len(plaintext) % block_size)
        plaintext.extend(bytes(padval for _ in range(padval)))
        return plaintext

    @staticmethod
    def verify(plaintext: bytearray | bytes | str, block_size: int) -> int:
        # Verifies that the padding is correct. Returns size of plaintext without padding.
        if block_size <= 0:
            raise ValueError("block size must be greater than 0")
        if not plaintext:
            raise ValueError("cannot verify padding for empty plaintext")
        if not isinstance(plaintext, bytearray):
            if isinstance(plaintext, str):
                plaintext = bytearray(plaintext, "utf-8")
            else:
                plaintext = bytearray(plaintext)

        pad = plaintext[-1]
        if not (0 < pad <= block_size) or any(plaintext[-1 - i] != pad for i in range(pad)):
            raise PaddingError
        return len(plaintext) - pad


class UUID:
    """Class to represent a UUID (Universally Unique Identifier).
    This is trimmed down version of the python uuid.UUID class.
    Since MicroPython does not have a built-in UUID module, we implement a basic version here.
    It will only support UUID version 4 (randomly generated UUIDs).
    """

    def __init__(self) -> None:
        self.int = int.from_bytes(CryptoUtils.generate_random_bytes(16), "big")

    def __str__(self):
        hex = "%032x" % self.int
        return "%s-%s-%s-%s-%s" % (hex[:8], hex[8:12], hex[12:16], hex[16:20], hex[20:])

    @property
    def bytes(self):
        return self.int.to_bytes(16)  # big endian


class EncryptionSession(CryptoUtils):
    """Class to represent an encryption session and it's internal state.

    i.e. sequence number which the device expects to increment.
    """

    def __init__(self, local_seed: bytes, remote_seed: bytes, auth_hash: bytes) -> None:
        self.local_seed = local_seed
        self.remote_seed = remote_seed
        self.auth_hash = auth_hash
        self._key = self._key_derive(local_seed, remote_seed, auth_hash)
        (self._iv, self._seq) = self._iv_derive(local_seed, remote_seed, auth_hash)
        self._sig = self._sig_derive(local_seed, remote_seed, auth_hash)

    def _key_derive(self, local_seed: bytes, remote_seed: bytes, user_hash: bytes) -> bytes:
        payload = b"lsk" + local_seed + remote_seed + user_hash
        return self.sha256(payload)[:16]

    def _unsigned_to_signed(self, value, bit_length):
        """
        Converts an unsigned integer to a signed integer of a specified bit-length.

        Args:
            value (int): The unsigned integer to convert.
            bit_length (int): The desired bit-length for the signed integer (e.g., 8, 16, 32).

        Returns:
            int: The signed integer representation.
        """
        if value >= (1 << (bit_length - 1)):  # Check if the sign bit is set
            return value - (1 << bit_length)
        else:
            return value

    def _iv_derive(
        self, local_seed: bytes, remote_seed: bytes, user_hash: bytes
    ) -> tuple[bytes, int]:
        # iv is first 16 bytes of sha256, where the last 4 bytes forms the
        # sequence number used in requests and is incremented on each request
        payload = b"iv" + local_seed + remote_seed + user_hash
        fulliv = self.sha256(payload)
        seq_unsigned = int.from_bytes(fulliv[-4:], "big")
        seq = self._unsigned_to_signed(seq_unsigned, 32)  # Convert to signed integer
        return (fulliv[:12], seq)

    def _sig_derive(self, local_seed: bytes, remote_seed: bytes, user_hash: bytes) -> bytes:
        # used to create a hash with which to prefix each request
        payload = b"ldk" + local_seed + remote_seed + user_hash
        return self.sha256(payload)[:28]

    def _generate_cipher(self) -> None:
        iv_seq = self._iv + self.pack_long(self._seq)
        return cryptolib.aes(self._key, 2, iv_seq)

    def encrypt(self, msg: bytes | str) -> tuple[bytes, int]:
        """Encrypt the data and increment the sequence number."""
        self._seq += 1
        encryptor = self._generate_cipher().encrypt

        if isinstance(msg, str):
            msg = msg.encode("utf-8")

        block_size = len(self._key)
        padded_data = PKCS7.pad(msg, block_size)
        ciphertext = encryptor(padded_data)
        signature = self.sha256(self._sig + self.pack_long(self._seq) + ciphertext)

        return (signature + ciphertext, self._seq)

    def decrypt(self, msg: bytes) -> str:
        """Decrypt the data."""
        decryptor = self._generate_cipher().decrypt
        dp = decryptor(msg[32:])
        # Remove padding
        plaintextlen = PKCS7.verify(dp, len(self._key))
        plaintextbytes = dp[:plaintextlen]

        return plaintextbytes.decode()


class ResponseError(Exception):
    pass


class HandshakeError(Exception):
    pass


class Protocol(CryptoUtils):
    def __init__(self, ip_address, username, password):
        self.ip_address = ip_address
        self.username = username
        self.password = password

    def _generate_auth_hash(self, username: str, password: str) -> bytes:
        return self.sha256(
            self.sha1(username.encode("utf-8")) + self.sha1(password.encode("utf-8"))
        )

    def _generate_handshake1_seed_auth_hash(
        self, local_seed: bytes, remote_seed: bytes, auth_hash: bytes
    ) -> bytes:
        """Generate a handshake hash using local seed, remote seed, and auth hash.
        :param local_seed: Local seed as bytes.
        :param remote_seed: Remote seed as bytes.
        :param auth_hash: Authentication hash as bytes.
        :return: SHA256 hash of the concatenated seeds and auth hash.
        """
        return self.sha256(local_seed + remote_seed + auth_hash)

    def _generate_handshake2_seed_auth_hash(
        self, remote_seed: bytes, local_seed: bytes, auth_hash: bytes
    ) -> bytes:
        """Generate a handshake hash using local seed, remote seed, and auth hash.
        :param remote_seed: Remote seed as bytes.
        :param local_seed: Local seed as bytes.
        :param auth_hash: Authentication hash as bytes.
        :return: SHA256 hash of the concatenated seeds and auth hash.
        """
        return self.sha256(remote_seed + local_seed + auth_hash)

    def _get_session_cookies(self, headers: dict) -> dict:
        """
        Extract session cookies from the response headers.
        :param headers: Response headers.
        :return: Session cookies as a dictionary.
        """
        cookies = {}
        if "Set-Cookie" in headers:
            for cookie in headers["Set-Cookie"].split(";"):
                if "=" in cookie:
                    key, value = cookie.split("=", 1)
                    cookies[key.strip()] = value.strip()
        return cookies

    def perform_handshake(
        self, ip_address: str, username: str, password: str
    ) -> tuple[EncryptionSession, dict]:
        local_seed = self.generate_seed()
        auth_hash = self._generate_auth_hash(username, password)

        # Handshake 1: send local_seed, receive remote_seed and session_id
        resp1 = self.send_func(ip_address, HANDSHAKE1, local_seed)
        remote_seed = resp1.data[0:16]
        server_hash = resp1.data[16:]
        msg = "Remote seed: {}, \nServer hash: {}".format(remote_seed.hex(), server_hash.hex())
        log.info(msg)
        headers = resp1.headers
        msg = "Handshake1 response headers: {}".format(headers)
        log.info(msg)

        # Send handshake1 seed and auth hash
        handshake1_hash = self._generate_handshake1_seed_auth_hash(
            local_seed, remote_seed, auth_hash
        )
        msg = "Handshake1 hash: {}".format(handshake1_hash.hex())
        log.info(msg)
        if handshake1_hash != server_hash:
            raise HandshakeError("Handshake1 hash mismatch")

        cookies = self._get_session_cookies(headers)
        msg = "Session cookies: {}".format(cookies)
        log.info(msg)
        session_cookie = {SESSION_COOKIE_NAME: cookies.get(SESSION_COOKIE_NAME, "")}

        payload2 = self._generate_handshake2_seed_auth_hash(remote_seed, local_seed, auth_hash)
        resp2 = self.send_func(ip_address, HANDSHAKE2, payload2, cookies=session_cookie)
        if not resp2.status_code == 200:
            raise ResponseError("Handshake2 verify failed")

        return EncryptionSession(local_seed, remote_seed, auth_hash), session_cookie

    # Example send_func for testing (replace with real network code)
    def send_func(
        self,
        ip_address: str,
        path: str,
        payload: bytes,
        cookies: dict | None = None,
        params: dict | None = None,
    ) -> requests.Response:
        # This function should send the payload to the device and return the response
        data: bytes = b""
        url = "http://{}/app/{}".format(ip_address, path)
        if params:
            url += "?" + "&".join(["{}={}".format(key, value) for key, value in params.items()])
        headers = {}
        if cookies:
            headers["Cookie"] = "; ".join(
                ["{}={}".format(key, value) for key, value in cookies.items()]
            )
        response = requests.post(url, data=payload, headers=headers, timeout=2)
        msg = "Sending to {} with payload: {}".format(url, payload)
        log.info(msg)
        msg = "Response status code: {}".format(response.status_code)
        log.info(msg)
        if not response.status_code == 200:
            raise ResponseError("Send to the device failed")

        msg = "Response status code: {}".format(response.status_code)
        log.info(msg)
        msg = "Response reason: {}".format(response.reason)
        log.info(msg)
        msg = "Response headers: {}".format(response.headers)
        log.debug(msg)
        response_headers = response.headers
        if "Content-Length" in response_headers:
            msg = "Content-Length: {}".format(response_headers["Content-Length"])
            log.debug(msg)
            content_length = int(response_headers["Content-Length"])
        try:
            if content_length > 0:
                data = b""
                remaining = content_length
                while remaining > 0:
                    chunk = response.raw.recv(min(2048, remaining))
                    if not chunk:
                        msg = "No more data received, remaining: {}".format(remaining)
                        log.warning(msg)
                        break
                    data += chunk
                    remaining -= len(chunk)
                msg = "Received {} bytes of data".format(len(data))
                log.info(msg)
            else:
                data = b""
            response.data = data
        except OSError as e:
            msg = "requests error: {}".format(e)
            log.error(msg)
        msg = "Response data length: {}".format(len(data))
        log.debug(msg)
        response.close()
        return response


class PaddingError(Exception):
    pass


class DeviceError(Exception):
    pass


class AuthenticationError(Exception):
    pass


# This Error Code class is a modified version of the original SmartErrorCode from python-kasa
class SmartErrorCode:
    """SMART Error Codes for Tapo devices."""

    @staticmethod
    def from_code(code: int) -> str:
        for attr in dir(SmartErrorCode):
            if not attr.startswith("__"):
                value = getattr(SmartErrorCode, attr)
                if isinstance(value, int) and value == code:
                    return "{}({})".format(attr, code)
        return "UNKNOWN_ERROR_CODE"

    SUCCESS = 0

    # Transport Errors
    SESSION_TIMEOUT_ERROR = 9999
    MULTI_REQUEST_FAILED_ERROR = 1200
    HTTP_TRANSPORT_FAILED_ERROR = 1112
    LOGIN_FAILED_ERROR = 1111
    HAND_SHAKE_FAILED_ERROR = 1100
    #: Real description unknown, seen after an encryption-changing fw upgrade
    TRANSPORT_UNKNOWN_CREDENTIALS_ERROR = 1003
    TRANSPORT_NOT_AVAILABLE_ERROR = 1002
    CMD_COMMAND_CANCEL_ERROR = 1001
    NULL_TRANSPORT_ERROR = 1000

    # Common Method Errors
    COMMON_FAILED_ERROR = -1
    UNSPECIFIC_ERROR = -1001
    UNKNOWN_METHOD_ERROR = -1002
    JSON_DECODE_FAIL_ERROR = -1003
    JSON_ENCODE_FAIL_ERROR = -1004
    AES_DECODE_FAIL_ERROR = -1005
    REQUEST_LEN_ERROR_ERROR = -1006
    CLOUD_FAILED_ERROR = -1007
    PARAMS_ERROR = -1008
    INVALID_PUBLIC_KEY_ERROR = -1010  # Unverified
    SESSION_PARAM_ERROR = -1101

    # Method Specific Errors
    QUICK_SETUP_ERROR = -1201
    DEVICE_ERROR = -1301
    DEVICE_NEXT_EVENT_ERROR = -1302
    FIRMWARE_ERROR = -1401
    FIRMWARE_VER_ERROR_ERROR = -1402
    LOGIN_ERROR = -1501
    TIME_ERROR = -1601
    TIME_SYS_ERROR = -1602
    TIME_SAVE_ERROR = -1603
    WIRELESS_ERROR = -1701
    WIRELESS_UNSUPPORTED_ERROR = -1702
    SCHEDULE_ERROR = -1801
    SCHEDULE_FULL_ERROR = -1802
    SCHEDULE_CONFLICT_ERROR = -1803
    SCHEDULE_SAVE_ERROR = -1804
    SCHEDULE_INDEX_ERROR = -1805
    COUNTDOWN_ERROR = -1901
    COUNTDOWN_CONFLICT_ERROR = -1902
    COUNTDOWN_SAVE_ERROR = -1903
    ANTITHEFT_ERROR = -2001
    ANTITHEFT_CONFLICT_ERROR = -2002
    ANTITHEFT_SAVE_ERROR = -2003
    ACCOUNT_ERROR = -2101
    STAT_ERROR = -2201
    STAT_SAVE_ERROR = -2202
    DST_ERROR = -2301
    DST_SAVE_ERROR = -2302

    VACUUM_BATTERY_LOW = -3001

    SYSTEM_ERROR = -40101
    INVALID_ARGUMENTS = -40209

    # Camera error codes
    SESSION_EXPIRED = -40401
    BAD_USERNAME = -40411  # determined from testing
    HOMEKIT_LOGIN_FAIL = -40412
    DEVICE_BLOCKED = -40404
    DEVICE_FACTORY = -40405
    OUT_OF_LIMIT = -40406
    OTHER_ERROR = -40407
    SYSTEM_BLOCKED = -40408
    NONCE_EXPIRED = -40409
    FFS_NONE_PWD = -90000
    TIMEOUT_ERROR = 40108
    UNSUPPORTED_METHOD = -40106
    ONE_SECOND_REPEAT_REQUEST = -40109
    INVALID_NONCE = -40413
    PROTOCOL_FORMAT_ERROR = -40210
    IP_CONFLICT = -40321
    DIAGNOSE_TYPE_NOT_SUPPORT = -69051
    DIAGNOSE_TASK_FULL = -69052
    DIAGNOSE_TASK_BUSY = -69053
    DIAGNOSE_INTERNAL_ERROR = -69055
    DIAGNOSE_ID_NOT_FOUND = -69056
    DIAGNOSE_TASK_NULL = -69057
    CLOUD_LINK_DOWN = -69060
    ONVIF_SET_WRONG_TIME = -69061
    CLOUD_NTP_NO_RESPONSE = -69062
    CLOUD_GET_WRONG_TIME = -69063
    SNTP_SRV_NO_RESPONSE = -69064
    SNTP_GET_WRONG_TIME = -69065
    LINK_UNCONNECTED = -69076
    WIFI_SIGNAL_WEAK = -69077
    LOCAL_NETWORK_POOR = -69078
    CLOUD_NETWORK_POOR = -69079
    INTER_NETWORK_POOR = -69080
    DNS_TIMEOUT = -69081
    DNS_ERROR = -69082
    PING_NO_RESPONSE = -69083
    DHCP_MULTI_SERVER = -69084
    DHCP_ERROR = -69085
    STREAM_SESSION_CLOSE = -69094
    STREAM_BITRATE_EXCEPTION = -69095
    STREAM_FULL = -69096
    STREAM_NO_INTERNET = -69097
    HARDWIRED_NOT_FOUND = -72101

    # Library internal for unknown error codes
    INTERNAL_UNKNOWN_ERROR = -100_000
    # Library internal for query errors
    INTERNAL_QUERY_ERROR = -100_001


class Device:
    def __init__(self, ip_address, username, password):
        self.ip_address = ip_address
        self.username = username
        self.password = password
        self.device_info = None
        self.device_name = None
        self.is_on = False
        self.protocol = Protocol(self.ip_address, self.username, self.password)
        self.encryption_session, self.session_cookie = self._authenticate()
        self.uuid = UUID()

    def _authenticate(self) -> tuple[EncryptionSession, dict]:
        return self.protocol.perform_handshake(self.ip_address, self.username, self.password)

    def _request(self, method: str, params: dict | None = None) -> str:
        """Send a request to the device using the encryption session."""
        if not self.encryption_session:
            raise AuthenticationError("Device is not authenticated")
        payload = {
            "method": method,
            "terminalUUID": str(self.uuid).upper(),
        }
        if params:
            payload["params"] = params
        msg = "Request payload: {}".format(payload)
        log.debug(msg)
        encrypted_payload, seq = self.encryption_session.encrypt(
            json.dumps(payload).encode("utf-8")
        )
        resp = self.protocol.send_func(
            self.ip_address,
            REQUEST_PATH,
            encrypted_payload,
            params={"seq": seq},
            cookies=self.session_cookie,
        )
        if not resp.status_code == 200:
            raise ResponseError("Request failed")
        decrypted_data = self.encryption_session.decrypt(resp.data)
        return decrypted_data

    def _device_command(self, method: str, params: dict | None = None) -> dict:
        response_raw = self._request(method, params)
        response = json.loads(response_raw)
        msg = "Device response: {}".format(response)
        log.debug(msg)
        if "error_code" in response and response["error_code"] != 0:
            raise DeviceError(
                "Error from device error_code: {}".format(
                    SmartErrorCode.from_code(response["error_code"])
                )
            )
        return response["result"] if "result" in response else None

    def get_device_info(self) -> dict:
        self.device_info = self._device_command("get_device_info")
        return self.device_info

    def get_device_name(self) -> str | None:
        if self.encryption_session:
            info = self.get_device_info()
            if "nickname" in info:
                nickname = info["nickname"]
                self.device_name = binascii.a2b_base64(nickname).decode("utf-8")
        return self.device_name

    def turn_on(self) -> str:
        self._device_command("set_device_info", {"device_on": True})
        return "Device turned on"

    def turn_off(self) -> str:
        self._device_command("set_device_info", {"device_on": False})
        return "Device turned off"

    def toggle(self) -> str:
        self.is_on = self.get_device_info().get("device_on", False)
        if self.is_on:
            return self.turn_off()
        else:
            return self.turn_on()

    def state(self) -> str:
        self.is_on = self.get_device_info().get("device_on", False)
        if self.is_on:
            return "Device is ON"
        else:
            return "Device is OFF"

    def set_state(self, on: bool) -> dict:
        """Set the device state."""
        return self._device_command("set_device_info", {"device_on": on})

    def get_countdown_rules(self) -> dict:
        """Get the countdown rules from the device."""
        return self._device_command("get_countdown_rules")

    def switch_with_delay(self, state: bool, delay: int = 0) -> dict:
        """Switch the device state with a delay.

        Args:
            state (bool): The desired state of the device.
            delay (int, optional): Delay in seconds before switching. Defaults to 0.

        Returns:
            dict: Response from the device.
        """
        # Check to see if the countdown rule already exists
        existing_rules = self.get_countdown_rules()
        if existing_rules and existing_rules.get("enable"):
            rule = existing_rules["rule_list"][0]
            return self._device_command(
                "edit_countdown_rule",
                {
                    "id": rule["id"],
                    "enable": True,
                    "delay": int(delay),
                    "desired_states": {"on": state},
                    "remain": int(delay),
                },
            )
        return self._device_command(
            "add_countdown_rule",
            {
                "delay": int(delay),
                "desired_states": {"on": state},
                "enable": True,
                "remain": int(delay),
            },
        )

    def stop_countdown(self) -> dict:
        """Stop the countdown timer on the device."""
        existing_rules = self.get_countdown_rules()
        if existing_rules and existing_rules.get("enable"):
            rule = existing_rules["rule_list"][0]
            return self._device_command(
                "edit_countdown_rule", {"id": rule["id"], "enable": False, "remain": 0, "delay": 0}
            )


class P115(Device):
    def __init__(self, ip_address: str, username: str, password: str, log_level: str = "WARNING"):
        if log_level in log_level_dict:
            log.setLevel(log_level_dict[log_level])
        else:
            msg = "Invalid log level: {}".format(log_level)
            logging.error(msg)
        super().__init__(ip_address, username, password)
