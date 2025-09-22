"""Helper functions for OAuth sidecar."""

import os
import httpx
from typing import Optional, Dict, Any
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def validate_google_oauth_token(access_token: str) -> Optional[Dict[str, Any]]:
    """
    Validate Google OAuth access token against Google's userinfo endpoint.
    
    Args:
        access_token: The OAuth access token to validate
        
    Returns:
        User info dict if token is valid, None otherwise
    """
    userinfo_url = "https://www.googleapis.com/oauth2/v2/userinfo"
    headers = {'Authorization': f'Bearer {access_token}'}
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(userinfo_url, headers=headers)
            if response.status_code == 200:
                user_info = response.json()
                logger.debug("Google OAuth token validated for user: %s", user_info.get('email'))
                return user_info
            else:
                logger.warning("Google OAuth token validation failed: HTTP %d", response.status_code)
                return None
    except Exception as e:
        logger.error("Error validating Google OAuth token: %s", str(e))
        return None


async def validate_google_oauth_token_with_client_check(
    access_token: str, 
    expected_client_id: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """
    Validate Google OAuth access token and optionally verify the client ID that issued it.
    
    Args:
        access_token: The OAuth access token to validate
        expected_client_id: Optional client ID to verify against (if None, skips client check)
        
    Returns:
        Dict with user info and token metadata if valid, None otherwise
        Format: {
            "user_info": {...},  # Standard userinfo response
            "token_info": {...}  # Token introspection response (includes aud/client_id)
        }
    """
    # First validate the token and get user info
    user_info = await validate_google_oauth_token(access_token)
    if not user_info:
        return None
    
    # If no client ID check requested, return just user info
    if not expected_client_id:
        return {"user_info": user_info, "token_info": None}
    
    # Perform token introspection to get client ID
    tokeninfo_url = "https://www.googleapis.com/oauth2/v1/tokeninfo"
    params = {'access_token': access_token}
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(tokeninfo_url, params=params)
            if response.status_code == 200:
                token_info = response.json()
                
                # Check if token was issued for the expected client
                token_audience = token_info.get('audience')  # 'audience' contains the client_id
                
                if token_audience == expected_client_id:
                    logger.info("Token client ID validated: %s for user %s", 
                              expected_client_id, user_info.get('email'))
                    return {
                        "user_info": user_info,
                        "token_info": token_info
                    }
                else:
                    logger.warning(
                        "Token client ID mismatch. Expected: %s, Got: %s for user %s",
                        expected_client_id, token_audience, user_info.get('email')
                    )
                    return {
                        "user_info": None,
                        "token_info": None,
                        "client_mismatch": True
                    }
            else:
                logger.warning("Google token introspection failed: HTTP %d", response.status_code)
                # Fall back to just user validation if introspection fails
                return {"user_info": user_info, "token_info": None}
                
    except Exception as e:
        logger.error("Error during token introspection: %s", str(e))
        # Fall back to just user validation if introspection fails
        return {"user_info": user_info, "token_info": None}


def check_req_env_vars(required_env_vars: list[str]):
    """Check that all required environment variables are set."""
    for var in required_env_vars:
        if os.getenv(var) is None:
            logger.error(f'Missing required environment variable: {var}')
            raise Exception(f'Missing required environment variable: {var}')


def extract_user_from_request(headers: Dict[str, str], query_params: Dict[str, str]) -> Optional[str]:
    """
    Extract OAuth Bearer token from request Authorization header.
    
    Args:
        headers: Request headers
        query_params: Query parameters (unused, kept for compatibility)
        
    Returns:
        OAuth access token if found, None otherwise
    """
    auth_header = headers.get("authorization", "")
    if auth_header.startswith("Bearer "):
        access_token = auth_header.removeprefix("Bearer ")
        logger.debug("Found Bearer token in Authorization header")
        return access_token
    
    logger.warning("No Bearer token found in Authorization header")
    return None
