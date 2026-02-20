from __future__ import annotations

import binascii
import hashlib
import hmac
import json
import struct
import urllib.parse
from datetime import datetime
from typing import Any, Optional
from urllib.parse import urlparse

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


EXTEND_HEADER = "algorithm=HMAC-SHA256, Access=%s, SignedHeaders=%s, Signature=%s"
TOTAL_STR = "HMAC-SHA256\n%s\n%s"
AUTH_HEADER_KEY = "Authorization"
SDK_HOST_KEY = "sdk-host"
CONTENT_TYPE_KEY = "content-type"
SDK_CONTENT_TYPE_KEY = "sdk-content-type"
DEFAULT_CONTENT_TYPE = "application/json"
SIGN_DATE_KEY = "sign-date"
AUTH_CODE_PARAMS = "%s+%s+%s+%s+%s+%s+%s+%s"
AUTH_CODE_PARAMS_NUM = 14


class Signature:
    def __init__(self, auth_code: Optional[str] = None, ak: Optional[str] = None, sk: Optional[str] = None):
        if ak and sk:
            self._access_key = ak
            self._secret_key = sk
        elif auth_code:
            self._access_key, self._secret_key = self._decode_auth_code(auth_code)
        else:
            raise ValueError("必须提供auth_code或ak/sk")

    def sign(self, req: requests.Request) -> None:
        if not req.url or not req.method:
            raise ValueError("请求URL和方法不能为空")

        payload = ""
        if req.data:
            payload = req.data if isinstance(req.data, str) else req.data.decode("utf-8")
        elif req.json:
            payload = json.dumps(req.json, ensure_ascii=False)

        host = self._get_host(req.url)
        req.headers, sign_date = self._header_check(req.headers, host)
        header_str, sign_header_str = self._sign_header_handler(req.headers)

        canonical_str = self._get_canonical_str(
            req.method,
            req.url,
            req.params,
            header_str,
            payload,
            sign_header_str,
        )

        hashed_canonical = self._sha256_hex_upper(canonical_str.encode("utf-8"))
        total_str = TOTAL_STR % (sign_date, hashed_canonical)
        signature = self._hmac_sha256_hex(self._secret_key, total_str)
        req.headers[AUTH_HEADER_KEY] = EXTEND_HEADER % (self._access_key, sign_header_str, signature)

    def _decode_auth_code(self, auth_code: str) -> tuple[str, str]:
        builder_str = self._reverse_hex(auth_code)
        builders = str(builder_str.decode("utf-8")).split("|")
        if len(builders) != AUTH_CODE_PARAMS_NUM:
            raise ValueError("联动码格式错误")
        aes_secret = self._calculate_aes_secret(builders)
        ak = self._aes_cbc_decrypt(builders[9], aes_secret)
        sk = self._aes_cbc_decrypt(builders[10], aes_secret)
        return ak, sk

    @staticmethod
    def _calculate_aes_secret(builders: list[str]) -> bytes:
        build_str = AUTH_CODE_PARAMS % (
            builders[0],
            builders[1],
            builders[2],
            builders[3],
            builders[4],
            builders[5],
            builders[6],
            builders[11],
        )
        return hashlib.sha256(build_str.encode("utf-8")).digest()

    @staticmethod
    def _get_host(uri: str) -> str:
        return urllib.parse.urlparse(uri).netloc

    @staticmethod
    def _header_check(headers: Optional[dict[str, Any]], host: str) -> tuple[dict[str, Any], str]:
        if headers is None:
            headers = {}
        if SDK_HOST_KEY not in headers:
            headers[SDK_HOST_KEY] = host
        if CONTENT_TYPE_KEY not in headers:
            headers[SDK_CONTENT_TYPE_KEY] = DEFAULT_CONTENT_TYPE
        else:
            headers[SDK_CONTENT_TYPE_KEY] = headers[CONTENT_TYPE_KEY]
        if SIGN_DATE_KEY not in headers:
            sign_date = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
            headers[SIGN_DATE_KEY] = sign_date
        else:
            sign_date = str(headers[SIGN_DATE_KEY])
        return headers, sign_date

    @staticmethod
    def _sign_header_handler(headers: dict[str, Any]) -> tuple[str, str]:
        header_pairs = sorted(headers.items(), key=lambda x: x[0].lower())
        header_builder = [f"{key}:{value}\n" for key, value in header_pairs]
        sign_header_builder = [f"{key};" for key, _ in header_pairs]
        sign_headers = "".join(sign_header_builder)
        if sign_headers:
            sign_headers = sign_headers[:-1]
        return "".join(header_builder), sign_headers

    def _get_canonical_str(
        self,
        method: str,
        uri: str,
        params: Any,
        headers_str: str,
        payload: str,
        sign_header_str: str,
    ) -> str:
        return "".join(
            [
                method,
                "\n",
                self._url_transform(uri),
                "\n",
                self._query_str_transform(params),
                "\n",
                headers_str,
                sign_header_str,
                "\n",
                self._payload_transform(payload),
            ]
        )

    @staticmethod
    def _url_transform(url_str: str) -> str:
        relative_path = urlparse(url_str).path
        if not relative_path.endswith("/"):
            relative_path += "/"
        return urllib.parse.quote(relative_path, encoding="utf-8")

    @staticmethod
    def _query_str_transform(params: Any) -> str:
        if not params:
            return ""
        if isinstance(params, dict):
            params = sorted(params.items(), key=lambda x: x[0])
            return urllib.parse.urlencode(params).replace("%3D", "=")
        return str(params)

    def _payload_transform(self, payload: str) -> str:
        if not payload:
            return self._sha256_hex_upper(b"")
        payload_bytes = payload.encode("utf-8")
        byte_values = [struct.unpack("b", bytes([byte]))[0] for byte in payload_bytes]
        byte_values.sort()
        normalized = bytearray()
        for byte in byte_values:
            normalized.append(byte)
        normalized = self._remove_spaces(normalized)
        return self._sha256_hex_upper(bytes(normalized))

    @staticmethod
    def _remove_spaces(b: bytearray) -> bytearray:
        j = 0
        for i in range(len(b)):
            if b[i] != 32:
                if i != j:
                    b[j] = b[i]
                j += 1
        return b[:j]

    @staticmethod
    def _hmac_sha256_hex(secret_key: str, data: str) -> str:
        mac = hmac.new(secret_key.encode("utf-8"), data.encode("utf-8"), hashlib.sha256)
        return binascii.hexlify(mac.digest()).decode("utf-8").upper()

    @staticmethod
    def _sha256_hex_upper(b: bytes) -> str:
        return binascii.hexlify(hashlib.sha256(b).digest()).decode("utf-8").upper()

    @staticmethod
    def _reverse_hex(auth_code: str) -> bytes:
        return binascii.unhexlify(auth_code)

    @staticmethod
    def _aes_cbc_decrypt(cipher_text: str, key: bytes) -> str:
        iv = b"\x00" * 16
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(bytes.fromhex(cipher_text)) + decryptor.finalize()
        return decrypted_data.decode("utf-8").rstrip("\x00")
