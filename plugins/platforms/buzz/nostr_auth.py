"""Dependency-free Nostr signing for Buzz WebSocket authentication."""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from typing import Any, Optional


FIELD_ORDER = 2**256 - 2**32 - 977
CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GENERATOR = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

Point = Optional[tuple[int, int]]


def _bech32_polymod(values: list[int]) -> int:
    generators = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = ((checksum & 0x1FFFFFF) << 5) ^ value
        for index, generator in enumerate(generators):
            if (top >> index) & 1:
                checksum ^= generator
    return checksum


def _bech32_hrp_expand(hrp: str) -> list[int]:
    return [ord(char) >> 5 for char in hrp] + [0] + [ord(char) & 31 for char in hrp]


def _decode_nsec(value: str) -> bytes:
    if value.lower() != value and value.upper() != value:
        raise ValueError("nsec cannot mix upper- and lowercase")
    normalized = value.lower()
    separator = normalized.rfind("1")
    if separator < 1 or separator + 7 > len(normalized):
        raise ValueError("invalid nsec encoding")
    hrp = normalized[:separator]
    if hrp != "nsec":
        raise ValueError("private key must use the nsec prefix")
    try:
        data = [BECH32_CHARSET.index(char) for char in normalized[separator + 1 :]]
    except ValueError as exc:
        raise ValueError("invalid character in nsec") from exc
    if _bech32_polymod(_bech32_hrp_expand(hrp) + data) != 1:
        raise ValueError("invalid nsec checksum")

    accumulator = 0
    bits = 0
    decoded = bytearray()
    for value5 in data[:-6]:
        accumulator = (accumulator << 5) | value5
        bits += 5
        while bits >= 8:
            bits -= 8
            decoded.append((accumulator >> bits) & 0xFF)
    if bits and (accumulator & ((1 << bits) - 1)):
        raise ValueError("non-zero nsec padding")
    if len(decoded) != 32:
        raise ValueError("nsec must encode exactly 32 bytes")
    return bytes(decoded)


def decode_private_key(value: str) -> int:
    raw = value.strip()
    if raw.lower().startswith("nsec1"):
        key_bytes = _decode_nsec(raw)
    else:
        try:
            key_bytes = bytes.fromhex(raw)
        except ValueError as exc:
            raise ValueError("private key must be 64 hex characters or nsec") from exc
        if len(key_bytes) != 32:
            raise ValueError("private key must be 32 bytes")
    key = int.from_bytes(key_bytes, "big")
    if not 1 <= key < CURVE_ORDER:
        raise ValueError("private key is outside the secp256k1 range")
    return key


def _point_add(left: Point, right: Point) -> Point:
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2:
        if (y1 + y2) % FIELD_ORDER == 0:
            return None
        slope = (3 * x1 * x1) * pow(2 * y1, FIELD_ORDER - 2, FIELD_ORDER)
    else:
        slope = (y2 - y1) * pow(x2 - x1, FIELD_ORDER - 2, FIELD_ORDER)
    slope %= FIELD_ORDER
    x3 = (slope * slope - x1 - x2) % FIELD_ORDER
    y3 = (slope * (x1 - x3) - y1) % FIELD_ORDER
    return x3, y3


def _point_multiply(scalar: int, point: Point = GENERATOR) -> Point:
    result: Point = None
    addend = point
    while scalar:
        if scalar & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        scalar >>= 1
    return result


def _tagged_hash(tag: str, payload: bytes) -> bytes:
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + payload).digest()


def public_key_hex(private_key: str) -> str:
    point = _point_multiply(decode_private_key(private_key))
    if point is None:  # pragma: no cover - range validation makes this unreachable
        raise ValueError("invalid private key")
    return point[0].to_bytes(32, "big").hex()


def schnorr_sign(
    message: bytes,
    private_key: str,
    *,
    auxiliary_randomness: Optional[bytes] = None,
) -> bytes:
    if len(message) != 32:
        raise ValueError("BIP-340 signs a 32-byte message")
    secret = decode_private_key(private_key)
    public_point = _point_multiply(secret)
    if public_point is None:  # pragma: no cover
        raise ValueError("invalid private key")
    public_x = public_point[0].to_bytes(32, "big")
    adjusted_secret = secret if public_point[1] % 2 == 0 else CURVE_ORDER - secret

    aux = (
        auxiliary_randomness
        if auxiliary_randomness is not None
        else secrets.token_bytes(32)
    )
    if len(aux) != 32:
        raise ValueError("auxiliary randomness must be 32 bytes")
    masked = bytes(
        left ^ right
        for left, right in zip(
            adjusted_secret.to_bytes(32, "big"),
            _tagged_hash("BIP0340/aux", aux),
        )
    )
    nonce = (
        int.from_bytes(
            _tagged_hash("BIP0340/nonce", masked + public_x + message), "big"
        )
        % CURVE_ORDER
    )
    if nonce == 0:
        raise RuntimeError("BIP-340 produced a zero nonce")
    nonce_point = _point_multiply(nonce)
    if nonce_point is None:  # pragma: no cover
        raise RuntimeError("BIP-340 produced an invalid nonce point")
    adjusted_nonce = nonce if nonce_point[1] % 2 == 0 else CURVE_ORDER - nonce
    nonce_x = nonce_point[0].to_bytes(32, "big")
    challenge = (
        int.from_bytes(
            _tagged_hash("BIP0340/challenge", nonce_x + public_x + message), "big"
        )
        % CURVE_ORDER
    )
    signature_scalar = (adjusted_nonce + challenge * adjusted_secret) % CURVE_ORDER
    return nonce_x + signature_scalar.to_bytes(32, "big")


def schnorr_verify(message: bytes, public_key_hex: str, signature_hex: str) -> bool:
    """Verify a strict lowercase-hex BIP-340 signature."""
    if len(message) != 32 or not _strict_lower_hex(public_key_hex, 64) or not _strict_lower_hex(signature_hex, 128):
        return False
    public_x = int(public_key_hex, 16)
    if public_x >= FIELD_ORDER:
        return False
    y_sq = (pow(public_x, 3, FIELD_ORDER) + 7) % FIELD_ORDER
    public_y = pow(y_sq, (FIELD_ORDER + 1) // 4, FIELD_ORDER)
    if pow(public_y, 2, FIELD_ORDER) != y_sq:
        return False
    if public_y & 1:
        public_y = FIELD_ORDER - public_y
    signature = bytes.fromhex(signature_hex)
    rx = int.from_bytes(signature[:32], "big")
    scalar = int.from_bytes(signature[32:], "big")
    if rx >= FIELD_ORDER or scalar >= CURVE_ORDER:
        return False
    challenge = int.from_bytes(
        _tagged_hash("BIP0340/challenge", signature[:32] + bytes.fromhex(public_key_hex) + message),
        "big",
    ) % CURVE_ORDER
    point = _point_add(_point_multiply(scalar), _point_multiply(CURVE_ORDER - challenge, (public_x, public_y)))
    return point is not None and point[1] % 2 == 0 and point[0] == rx


def _strict_lower_hex(value: object, length: int) -> bool:
    return isinstance(value, str) and len(value) == length and all(c in "0123456789abcdef" for c in value)


def _validate_conditions(conditions: str) -> list[tuple[str, int]]:
    parsed: list[tuple[str, int]] = []
    if not conditions:
        return parsed
    if any(c.isspace() for c in conditions):
        raise ValueError("NIP-OA conditions must not contain whitespace")
    for clause in conditions.split("&"):
        if clause.startswith("kind="):
            value, maximum = clause[5:], 65535
        elif clause.startswith("created_at<") or clause.startswith("created_at>"):
            value, maximum = clause[11:], 4294967295
        else:
            raise ValueError("unsupported NIP-OA condition")
        if not value.isascii() or not value.isdecimal() or (len(value) > 1 and value[0] == "0"):
            raise ValueError("NIP-OA condition must use canonical decimal")
        if int(value) > maximum:
            raise ValueError("NIP-OA condition is out of range")
        parsed.append((clause[:len(clause) - len(value)], int(value)))
    return parsed


def verify_auth_tag(auth_tag: list[str], agent_pubkey: str) -> str:
    """Validate NIP-OA grammar/signature and return its owner pubkey."""
    if not isinstance(auth_tag, list) or len(auth_tag) != 4 or not all(isinstance(v, str) for v in auth_tag):
        raise ValueError("BUZZ_AUTH_TAG must be a four-string auth tag")
    label, owner, conditions, signature = auth_tag
    if label != "auth" or not _strict_lower_hex(owner, 64) or not _strict_lower_hex(agent_pubkey, 64):
        raise ValueError("BUZZ_AUTH_TAG contains an invalid label or pubkey")
    if owner == agent_pubkey:
        raise ValueError("NIP-OA self-attestation is invalid")
    _validate_conditions(conditions)
    message = hashlib.sha256(f"nostr:agent-auth:{agent_pubkey}:{conditions}".encode()).digest()
    if not schnorr_verify(message, owner, signature):
        raise ValueError("BUZZ_AUTH_TAG signature verification failed")
    return owner


def verify_auth_tag_for_event(
    auth_tag: list[str], agent_pubkey: str, *, kind: int, created_at: int
) -> str:
    """Validate a NIP-OA tag, including every constraint on the exact event."""
    owner = verify_auth_tag(auth_tag, agent_pubkey)
    for operator, value in _validate_conditions(auth_tag[2]):
        if operator == "kind=" and int(kind) != value:
            raise ValueError("NIP-OA kind condition is not satisfied")
        if operator == "created_at<" and int(created_at) >= value:
            raise ValueError("NIP-OA created_at condition is not satisfied")
        if operator == "created_at>" and int(created_at) <= value:
            raise ValueError("NIP-OA created_at condition is not satisfied")
    return owner


def build_auth_event(
    *,
    private_key: str,
    challenge: str,
    relay_url: str,
    auth_tag_json: str = "",
    created_at: Optional[int] = None,
    auxiliary_randomness: Optional[bytes] = None,
) -> dict[str, Any]:
    timestamp = int(time.time()) if created_at is None else int(created_at)
    tags: list[list[str]] = [
        ["relay", relay_url],
        ["challenge", challenge],
    ]
    if auth_tag_json.strip():
        try:
            auth_tag = json.loads(auth_tag_json)
        except json.JSONDecodeError as exc:
            raise ValueError("BUZZ_AUTH_TAG is not valid JSON") from exc
        if (
            not isinstance(auth_tag, list)
            or len(auth_tag) != 4
            or auth_tag[0] != "auth"
            or not all(isinstance(part, str) for part in auth_tag)
        ):
            raise ValueError("BUZZ_AUTH_TAG must be a four-string auth tag")
        verify_auth_tag_for_event(
            auth_tag,
            public_key_hex(private_key),
            kind=22242,
            created_at=timestamp,
        )
        tags.append(auth_tag)

    return build_signed_event(
        private_key=private_key,
        kind=22242,
        tags=tags,
        content="",
        created_at=timestamp,
        auxiliary_randomness=auxiliary_randomness,
    )


def build_signed_event(
    *,
    private_key: str,
    kind: int,
    tags: list[list[str]],
    content: str,
    created_at: Optional[int] = None,
    auxiliary_randomness: Optional[bytes] = None,
) -> dict[str, Any]:
    """Build a canonical signed Nostr event without third-party dependencies."""
    pubkey = public_key_hex(private_key)
    timestamp = int(time.time()) if created_at is None else int(created_at)
    serialized = json.dumps(
        [0, pubkey, timestamp, int(kind), tags, content],
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()
    event_id = hashlib.sha256(serialized).digest()
    return {
        "id": event_id.hex(),
        "pubkey": pubkey,
        "created_at": timestamp,
        "kind": int(kind),
        "tags": tags,
        "content": content,
        "sig": schnorr_sign(
            event_id,
            private_key,
            auxiliary_randomness=auxiliary_randomness,
        ).hex(),
    }
