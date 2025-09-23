"""Token validation functionality for OAuth service."""

import time
from typing import NamedTuple

from .gcp.google_wif import google_wif_config


class ValidationResult(NamedTuple):
    """Result of token validation."""

    is_valid: bool
    client_id: str | None = None
    user_email: str | None = None
    user_name: str | None = None
    expires_at: float | None = None
    error: str | None = None


# In-memory cache for token validation results
_token_cache: dict[str, ValidationResult] = {}
_cache_ttl = 300  # 5 minutes


async def validate_oauth_token(
    token: str, expected_client_id: str | None = None
) -> ValidationResult:
    """
    Validate OAuth token using Google Workspace validation.

    Args:
        token: OAuth access token to validate
        expected_client_id: Optional client ID to validate against. If None, will try to get from OAuth config.

    Returns:
        ValidationResult with validation status and details
    """
    # Check cache first
    if token in _token_cache:
        result = _token_cache[token]
        if result.expires_at and result.expires_at > time.time():
            return result
        else:
            # Remove expired cache entry
            del _token_cache[token]

    try:
        # Get expected client ID from OAuth configuration if not provided
        if expected_client_id is None:
            from . import server

            expected_client_id = server.get_oauth_client_id()

        # Validate token against Google Workspace using WIF
        google_result = await google_wif_config.validate_oauth_token(
            token, expected_client_id=expected_client_id
        )

        if google_result.is_valid and google_result.user_info:
            result = ValidationResult(
                is_valid=True,
                client_id=expected_client_id,
                user_email=google_result.user_info.email,
                user_name=google_result.user_info.name,
                expires_at=None,  # We'll use cache TTL instead
            )
        else:
            # Map Google validation errors to our error types
            error_msg = google_result.error_description or "Token validation failed"
            result = ValidationResult(is_valid=False, error=error_msg)

        # Cache the result
        cache_expires_at = time.time() + _cache_ttl
        cached_result = ValidationResult(
            is_valid=result.is_valid,
            client_id=result.client_id,
            user_email=result.user_email,
            user_name=result.user_name,
            expires_at=cache_expires_at,
            error=result.error,
        )
        _token_cache[token] = cached_result

        return result

    except Exception as e:
        return ValidationResult(
            is_valid=False, error=f"Unexpected error during token validation: {e!s}"
        )


def clear_token_cache() -> None:
    """Clear the token validation cache."""
    global _token_cache
    _token_cache.clear()
