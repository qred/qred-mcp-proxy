"""OAuth sidecar client for token validation."""

import os
import httpx
from typing import Optional, NamedTuple


class ValidationResult(NamedTuple):
    """Result of token validation from OAuth sidecar."""
    is_valid: bool
    client_id: Optional[str] = None
    user_email: Optional[str] = None
    user_name: Optional[str] = None
    error: Optional[str] = None


class OAuthSidecarClient:
    """Client for communicating with OAuth sidecar service."""
    
    def __init__(self, oauth_service_url: Optional[str] = None):
        """
        Initialize OAuth sidecar client.
        
        Args:
            oauth_service_url: Base URL of the OAuth sidecar service.
                              Defaults to OAUTH_SERVICE_URL env var or http://localhost:8001
        """
        self.oauth_service_url = oauth_service_url or os.getenv(
            "OAUTH_SERVICE_URL", "http://localhost:8001"
        )
        self.validate_url = f"{self.oauth_service_url}/validate"
    
    async def validate_token(self, token: str) -> ValidationResult:
        """
        Validate OAuth token using the sidecar service.
        
        Args:
            token: OAuth access token to validate
            
        Returns:
            ValidationResult with validation status and details
        """
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.validate_url,
                    json={"token": token},
                    timeout=10.0
                )
                
                if response.status_code == 200:
                    data = response.json()
                    return ValidationResult(
                        is_valid=data.get("valid", False),
                        client_id=data.get("client_id"),
                        user_email=data.get("user_email"),
                        user_name=data.get("user_name"),
                        error=data.get("error")
                    )
                else:
                    return ValidationResult(
                        is_valid=False,
                        error=f"OAuth service returned {response.status_code}: {response.text}"
                    )
                    
        except httpx.RequestError as e:
            return ValidationResult(
                is_valid=False,
                error=f"Failed to connect to OAuth service: {str(e)}"
            )
        except Exception as e:
            return ValidationResult(
                is_valid=False,
                error=f"Token validation error: {str(e)}"
            )


# Global instance
_oauth_client: Optional[OAuthSidecarClient] = None


def get_oauth_client() -> OAuthSidecarClient:
    """Get the global OAuth sidecar client instance."""
    global _oauth_client
    if _oauth_client is None:
        _oauth_client = OAuthSidecarClient()
    return _oauth_client


async def validate_request_user(token: str) -> ValidationResult:
    """
    Validate user token via OAuth sidecar.
    
    Args:
        token: OAuth access token
        
    Returns:
        ValidationResult with validation status
    """
    client = get_oauth_client()
    return await client.validate_token(token)
