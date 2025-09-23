"""Google Workload Identity Federation for OAuth sidecar."""

import json
import logging
import os
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import boto3
import google.oauth2.credentials
import requests
from google.auth import environment_vars
from google.auth.aws import Credentials as AWSCredentials
from google.auth.transport.requests import AuthorizedSession
from googleapiclient.discovery import Resource, build
from requests.exceptions import HTTPError

from ..utils.helpers import (
    check_req_env_vars,
    validate_google_oauth_token,
    validate_google_oauth_token_with_client_check,
)

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
auth_logger = logging.getLogger(f"{__name__}.auth")


@dataclass
class UserInfo:
    """User information from Google Workspace."""

    email: str
    name: str | None = None
    is_valid: bool = True
    permissions: list[str] | None = None

    def __post_init__(self) -> None:
        if self.permissions is None:
            self.permissions = ["mcp:read", "mcp:write"]


@dataclass
class ValidationResult:
    """Result of OAuth token validation with detailed error information."""

    user_info: UserInfo | None = None
    is_valid: bool = False
    error_type: str | None = (
        None  # "invalid_token", "invalid_client", "workspace_denied", "group_access_denied", "group_validation_error"
    )
    error_description: str | None = None


class GoogleWIF:
    """Google Workload Identity Federation for OAuth validation."""

    def __init__(self) -> None:
        """Initialize Google WIF configuration."""
        required_env_vars = [
            "SA_EMAIL",
            "GOOGLE_ADMIN_EMAIL",
            "GOOGLE_CUSTOMER_ID",
            "GCP_SECRET_ARN",
        ]
        check_req_env_vars(required_env_vars)

        self.sa_email: str = os.getenv("SA_EMAIL", "")
        self.google_api_auth_scopes: list[str] = [
            "https://www.googleapis.com/auth/cloud-platform"
        ]

        # Parse the Google WIF configuration from environment variable
        try:
            gcp_secret_json = os.getenv("GCP_SECRET_ARN", "")
            if not gcp_secret_json.strip():
                raise ValueError(
                    "GCP_SECRET_ARN environment variable is empty or not set"
                )

            self.sa_info: dict[str, Any] = json.loads(gcp_secret_json)

            if not self.sa_info:
                raise ValueError("Parsed JSON from GCP_SECRET_ARN is empty")

            auth_logger.info(
                f"Successfully loaded Google WIF configuration for audience: {self.sa_info.get('audience', 'unknown')}"
            )

        except json.JSONDecodeError as e:
            auth_logger.error(f"Failed to parse GCP_SECRET_ARN as JSON: {e}")
            raise ValueError(
                f"Invalid JSON in GCP_SECRET_ARN environment variable: {e}"
            ) from e
        except ValueError as e:
            auth_logger.error(f"Google WIF configuration error: {e}")
            raise
        except Exception as e:
            auth_logger.error(f"Unexpected error loading Google WIF configuration: {e}")
            raise ValueError(f"Failed to load Google WIF configuration: {e}") from e

        self.user_agent: str = os.getenv("GOOGLE_USER_AGENT", "mcp-oauth-proxy")
        self.admin_service: Resource | None = None
        self.google_users: dict[str, dict[str, Any]] | None = None
        self.credentials: google.oauth2.credentials.Credentials | None = None

        # Google Workspace admin email for directory access
        # This should be a service account with admin privileges
        self.impersonation_email: str = os.getenv(
            "GOOGLE_ADMIN_EMAIL", "admin@your-domain.com"
        )

        # Google Workspace customer ID for Directory API calls
        self.google_customer_id: str = os.getenv("GOOGLE_CUSTOMER_ID", "my_customer_id")

        # Default organizational unit path for user searches
        self.default_org_unit_path: str = os.getenv("GOOGLE_ORG_UNIT_PATH", "/")

        # Workspace domain for group searches
        self.workspace_domain: str = os.getenv(
            "GOOGLE_WORKSPACE_DOMAIN", "your-domain.com"
        )

        self.target_scopes: list[str] = [
            "https://www.googleapis.com/auth/admin.directory.user.readonly",
            "https://www.googleapis.com/auth/admin.directory.group.readonly",
        ]
        self.expiration: datetime = datetime.now(UTC)

        # User data management
        self.last_users_refresh: dict[str, datetime] = {}
        self.users_refresh_interval: int = 600  # 10 minutes in seconds

        # Group data management
        self.google_team_groups: dict[str, list[str]] | None = None
        self.last_groups_refresh: dict[str, datetime] = {}
        self.groups_refresh_interval: int = 600  # 10 minutes in seconds

        # AWS credential management for long-running processes
        self._boto_session: boto3.Session | None = None
        self._credential_refresh_lock = False

        # Build the users and groups lookup dictionaries at startup
        # Note: Users are loaded immediately, but groups are only initialized empty
        # The server startup process will populate groups before accepting requests
        self.__get_users(self.default_org_unit_path)
        self.__initialize_groups()

    def _get_refreshable_aws_session(self) -> boto3.Session:
        """
        Get a refreshable boto3 session that properly handles ECS credential refresh.

        This method ensures that AWS credentials are automatically refreshed when they expire by using the same session,
        which is critical for long-running processes in ECS where credentials have limited lifetimes.
        """
        if self._boto_session is None or self._credential_refresh_lock:
            auth_logger.debug("Creating new refreshable boto3 session")

            # Simply create a fresh session - boto3 will handle ECS credential refresh automatically
            # The key is to create a new session rather than reusing cached ones
            self._boto_session = boto3.Session()

            auth_logger.debug("Created refreshable boto3 session")

        return self._boto_session

    def _force_credential_refresh(self) -> None:
        """
        Force AWS credential refresh by clearing cached sessions and credential providers.

        This method clears all cached credential providers to force boto3 to fetch fresh
        credentials from the ECS metadata service.
        """
        if self._credential_refresh_lock:
            auth_logger.debug("Credential refresh already in progress, skipping")
            return

        try:
            self._credential_refresh_lock = True
            auth_logger.info("Forcing AWS credential refresh for long-running process")

            # Clear the existing session to force recreation
            self._boto_session = None

            # Clear the global default session to force credential re-fetch
            # This is the most reliable way to force credential refresh in boto3
            if hasattr(boto3, "_get_default_session"):
                # Clear the internal default session
                boto3.DEFAULT_SESSION = None

            # Create a fresh session instance - this will automatically create a new default session
            self._boto_session = boto3.Session()

            auth_logger.info("Successfully forced AWS credential refresh")

        except Exception as e:
            auth_logger.warning(
                "Failed to force credential refresh (non-critical): %s", e
            )
        finally:
            self._credential_refresh_lock = False

    def __generate_oauth2_client_credentials(self) -> None:
        """Generate OAuth2 client credentials for Google API access with retry for expired AWS credentials."""

        max_retries = 2
        for attempt in range(max_retries):
            try:
                auth_logger.info(
                    "Starting impersonation (attempt %d/%d)", attempt + 1, max_retries
                )

                new_expiration = datetime.now(UTC)
                unsigned_jwt = self.__build_domain_wide_delegation_jwt(
                    self.sa_email,
                    self.impersonation_email,
                    self.target_scopes,
                    3600,  # 1 hour
                )

                # Update credential source URLs for ECS environment
                # Use refreshable session instead of creating new session each time
                session = self._get_refreshable_aws_session()
                aws_credentials = session.get_credentials()

                # Check if we got valid credentials
                if aws_credentials is None:
                    raise ValueError("Unable to obtain AWS credentials from session")

                # Get the actual credential values
                # Note: boto3 automatically handles credential refresh when needed
                frozen_creds = aws_credentials.get_frozen_credentials()

                # Log credential info for debugging (without exposing sensitive values)
                auth_logger.debug(
                    "AWS credentials obtained - access_key: %s..., has_token: %s",
                    frozen_creds.access_key[:8] if frozen_creds.access_key else "None",
                    bool(frozen_creds.token),
                )

                # Check if credentials have expiration info (for ECS task credentials)
                if hasattr(aws_credentials, "_expiry_time") and getattr(
                    aws_credentials, "_expiry_time", None
                ):
                    try:
                        expiry_time = aws_credentials._expiry_time
                        time_until_expiry = expiry_time - datetime.now(UTC)  # type: ignore[operator]
                        auth_logger.info(
                            "AWS credentials expire in: %s", time_until_expiry
                        )

                        # Proactively refresh if credentials expire soon (within 5 minutes)
                        if time_until_expiry.total_seconds() < 300:  # 5 minutes
                            auth_logger.warning(
                                "AWS credentials expire soon (%s), forcing complete credential refresh",
                                time_until_expiry,
                            )
                            try:
                                self._force_credential_refresh()
                                # Get fresh credentials from the new session
                                session = self._get_refreshable_aws_session()
                                aws_credentials = session.get_credentials()
                                if aws_credentials:
                                    frozen_creds = (
                                        aws_credentials.get_frozen_credentials()
                                    )
                                    auth_logger.info(
                                        "Successfully performed complete credential refresh for expiring credentials"
                                    )
                                else:
                                    auth_logger.warning(
                                        "Complete credential refresh succeeded but no credentials available"
                                    )
                            except Exception as proactive_refresh_error:
                                auth_logger.warning(
                                    "Proactive complete credential refresh failed: %s",
                                    proactive_refresh_error,
                                )

                    except Exception as exp_error:
                        auth_logger.debug(
                            "Could not determine credential expiry: %s", exp_error
                        )

                os.environ[environment_vars.AWS_ACCESS_KEY_ID] = frozen_creds.access_key
                os.environ[environment_vars.AWS_SECRET_ACCESS_KEY] = (
                    frozen_creds.secret_key
                )
                os.environ[environment_vars.AWS_SESSION_TOKEN] = frozen_creds.token

                # Sign JWT using iamcredentials endpoint
                authed_session = AuthorizedSession(
                    AWSCredentials.from_info(self.sa_info).with_scopes(
                        self.google_api_auth_scopes
                    )
                )

                url = f"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{self.sa_email}:signJwt"
                body = {"payload": unsigned_jwt}

                response = authed_session.post(url=url, json=body)
                try:
                    signed_jwt = response.json()["signedJwt"]
                except Exception as e:
                    logger.debug(response.json())
                    raise e

                if not signed_jwt:
                    raise ValueError("No data in response")

                logger.debug("Got signedJwt")

                # Exchange signed JWT for OAuth2 access token
                access_token = self.__generate_domain_wide_delegation_access_token(
                    signed_jwt
                )

                # Set new expiration
                self.expiration = new_expiration

                # Create credential client with access token
                self.credentials = google.oauth2.credentials.Credentials(access_token)

                auth_logger.info("Impersonation credentials received successfully")
                return  # Success, exit retry loop

            except Exception as e:
                if self.__is_credential_expired_error(e) and attempt < max_retries - 1:
                    auth_logger.warning(
                        "AWS credentials expired on attempt %d/%d, forcing credential refresh: %s",
                        attempt + 1,
                        max_retries,
                        e,
                    )

                    # Use the new refreshable session method to force credential refresh
                    self._force_credential_refresh()
                    time.sleep(1)  # Brief delay before retry
                    continue
                else:
                    auth_logger.error(
                        "Failed to generate OAuth2 credentials after %d attempts: %s",
                        attempt + 1,
                        e,
                    )
                    raise

    def __is_credential_expired_error(self, error: Exception) -> bool:
        """Check if the error indicates expired AWS credentials."""
        error_str = str(error).lower()
        return any(
            phrase in error_str
            for phrase in [
                "expired token",
                "expiredtoken",
                "invalid_grant",
                "token has expired",
                "credentials have expired",
            ]
        )

    def __build_domain_wide_delegation_jwt(
        self, service_account: str, subject: str, scopes: list[str], lifetime: int
    ) -> str:
        """Create the payload to sign with JWT."""
        now = int(time.time())
        body = {
            "iss": service_account,
            "aud": "https://oauth2.googleapis.com/token",
            "iat": now,
            "exp": now + lifetime,
        }
        if subject and subject.strip():
            body["sub"] = subject
        if scopes:
            body["scope"] = " ".join(scopes)

        logger.debug(json.dumps(body))
        return json.dumps(body)

    def __generate_domain_wide_delegation_access_token(self, signed_jwt: str) -> str:
        """Use the signed JWT to create a domain-wide delegation access token."""
        url = "https://oauth2.googleapis.com/token"
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": self.user_agent,
        }
        data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": signed_jwt,
        }

        try:
            response = requests.post(url, headers=headers, data=data, timeout=30)
            response.raise_for_status()
            return str(response.json()["access_token"])

        except HTTPError as e:
            auth_logger.error(f"Error requesting oauth token: {e}")
            raise
        except Exception as e:
            auth_logger.error(f"Uncaught exception: {e}")
            raise

    def __get_admin_service(self) -> None:
        """Build the admin service."""
        self.__generate_oauth2_client_credentials()
        self.admin_service = build(
            "admin", "directory_v1", credentials=self.credentials, cache_discovery=False
        )
        logger.info("Built admin service")

    def __get_users(self, org_unit_path: str | None = None) -> None:
        """
        This function fetches all users' information at once.
        Implements a timeout mechanism to avoid excessive API calls.

        Args:
            org_unit_path: The organizational unit path to fetch users from. If None, uses default.
        """
        # Use default org unit path if none provided
        if org_unit_path is None:
            org_unit_path = self.default_org_unit_path

        # Check if we've refreshed users for this org_unit_path recently
        now = datetime.now(UTC)
        last_refresh = self.last_users_refresh.get(org_unit_path)

        if (
            last_refresh
            and (now - last_refresh).total_seconds() < self.users_refresh_interval
        ):
            logger.info(
                "✅ USERS: Skipping user refresh for %s - last refresh was %d seconds ago (interval: %d seconds)",
                org_unit_path,
                (now - last_refresh).total_seconds(),
                self.users_refresh_interval,
            )
            return

        google_users: dict[str, dict[str, Any]] = {}
        try:
            if not self.admin_service or (self.expiration < now):
                self.__get_admin_service()

            # Type guard to ensure admin_service is not None
            assert self.admin_service is not None, "Admin service should be initialized"

            logger.info(
                "Fetching Google Workspace users for org unit: %s", org_unit_path
            )
            page_token: str | None = None
            user_count = 0

            while True:
                # Use type: ignore for Google API dynamic attributes
                user_response = (
                    self.admin_service.users()
                    .list(  # type: ignore[attr-defined]
                        customer=self.google_customer_id,
                        projection="basic",
                        query=f"orgUnitPath='{org_unit_path}'",
                        viewType="admin_view",
                        pageToken=page_token,
                    )
                    .execute()
                )
                users: list[dict[str, Any]] = user_response.get("users", [])

                for user in users:
                    primary_email = user.get("primaryEmail")
                    if primary_email:
                        google_users[primary_email] = user
                        user_count += 1

                page_token = user_response.get("nextPageToken")
                if not page_token:
                    break

            # Update refresh timestamp on successful completion
            self.last_users_refresh[org_unit_path] = now
            logger.info(
                "Successfully fetched %d users for org unit: %s",
                user_count,
                org_unit_path,
            )

        except Exception as e:
            logger.warning(
                "Error fetching users for %s. The error was %s", org_unit_path, e
            )

        # Always update the google_users regardless of success/failure
        logger.debug(
            f"Completed user refresh for organizational unit path: {org_unit_path}"
        )
        self.google_users = google_users

    def __initialize_groups(self) -> None:
        """
        Initialize groups dictionary at startup.

        Note: We initialize an empty dictionary here rather than fetching groups immediately because:
        1. We don't know which groups are needed until server configuration is loaded
        2. The server startup process (_refresh_groups_and_users) will populate this with actual
           group data for all required groups before accepting requests
        3. This ensures the dictionary exists and is ready for the server's initial population
        """
        self.google_team_groups = {}
        logger.info(
            "Initialized empty groups lookup dictionary (will be populated by server startup process)"
        )

    async def refresh_groups(self, groups: list[str]) -> None:
        """
        Refresh group membership data for the specified groups.
        This can be called during startup or for periodic refreshes.

        Args:
            groups: List of group names to refresh
        """
        if not groups:
            logger.info("No groups to refresh")
            return

        logger.info(f"Loading {len(groups)} groups: {sorted(groups)}")
        try:
            await self.__get_group_members(groups, force_refresh=True)
            logger.info(f"✅ Successfully loaded {len(groups)} groups")
        except Exception as e:
            logger.warning(f"Failed to load groups: {e}")
            # Don't fail if group refresh fails

    def refresh_users(self, org_unit_path: str | None = None) -> None:
        """
        Refresh user data for the specified organizational unit.
        This can be called during startup or for periodic refreshes.

        Args:
            org_unit_path: The organizational unit path to refresh users from. If None, uses default.
        """
        if org_unit_path is None:
            org_unit_path = self.default_org_unit_path

        logger.info(f"Refreshing users for org unit: {org_unit_path}")
        try:
            # Force a refresh by clearing the last refresh timestamp
            if org_unit_path in self.last_users_refresh:
                del self.last_users_refresh[org_unit_path]

            # Call the internal user refresh method
            self.__get_users(org_unit_path)
            logger.info(
                f"✅ Successfully refreshed users for org unit: {org_unit_path}"
            )
        except Exception as e:
            logger.warning(f"Failed to refresh users for {org_unit_path}: {e}")
            # Don't fail if user refresh fails

    async def __get_user(
        self, user_identifier: str, org_unit_path: str | None = None
    ) -> UserInfo:
        """Get a specific user from Google Workspace with intelligent caching."""
        # Use default org unit path if none provided
        if org_unit_path is None:
            org_unit_path = self.default_org_unit_path

        user: dict[str, Any] = {}
        is_valid = False

        # Initial user lookup check
        if not self.google_users:
            self.__get_users(org_unit_path)

        # Type guard to ensure google_users is not None
        if self.google_users is not None:
            auth_logger.info("🔍 USER LOOKUP: searching for user: %s", user_identifier)
            user_data = self.google_users.get(user_identifier)
            if user_data:
                # User found on first try
                auth_logger.info(
                    "✅ USER LOOKUP HIT: Found user %s in lookup", user_identifier
                )
                user = user_data
                is_valid = True
            else:
                # Check if we can refresh the data (respect interval)
                now = datetime.now(UTC)
                last_refresh = self.last_users_refresh.get(org_unit_path)

                if (
                    not last_refresh
                    or (now - last_refresh).total_seconds()
                    >= self.users_refresh_interval
                ):
                    auth_logger.warning(
                        "User not found in Google Workspace: %s. Attempting to refresh user data",
                        user_identifier,
                    )
                    self.__get_users(org_unit_path)
                    # Check again after refresh
                    if self.google_users is not None:
                        user_data = self.google_users.get(user_identifier)
                        if user_data:
                            auth_logger.debug(
                                "Found user %s after refreshing google users",
                                user_identifier,
                            )
                            user = user_data
                            is_valid = True
                        else:
                            logger.warning(
                                "User not found in Google Workspace: %s (even after refresh)",
                                user_identifier,
                            )
                else:
                    time_until_refresh = (
                        self.users_refresh_interval
                        - (now - last_refresh).total_seconds()
                    )
                    logger.warning(
                        "User %s not found in lookup. Next data refresh allowed in %.0f seconds",
                        user_identifier,
                        time_until_refresh,
                    )
        else:
            logger.error("Failed to initialize Google users lookup")

        # Extract user information
        if is_valid:
            name = user.get("name") or user.get("displayName")
        else:
            name = user_identifier.split("@")[0]

        auth_logger.info(
            "Validated Google user: %s (%s). Is user valid? %s",
            user_identifier,
            name,
            is_valid,
        )

        return UserInfo(
            email=user_identifier,
            name=name,
            is_valid=is_valid,
            permissions=["mcp:read", "mcp:write"] if is_valid else [],
        )

    async def __get_group_members(
        self, groups: list[str], force_refresh: bool = False
    ) -> dict[str, list[str]]:
        """
        Get the group members of the requested groups with intelligent caching.
        Requires a google admin sdk credential with at least groups.readonly scope.

        Args:
            groups: List of group names (without domain suffix)
            force_refresh: If True, refresh data even if current. If False, return current data when available.

        Returns:
            Dictionary mapping group names to lists of member emails
        """
        # Check if we need to refresh group data
        now = datetime.now(UTC)

        # Check which groups need to be refreshed or can use current data
        groups_to_refresh = []
        current_groups = {}
        stale_groups = {}

        for group in groups:
            last_refresh = self.last_groups_refresh.get(group)

            if self.google_team_groups is not None and group in self.google_team_groups:
                if (
                    last_refresh
                    and (now - last_refresh).total_seconds()
                    < self.groups_refresh_interval
                ):
                    # Fresh data for this group
                    current_groups[group] = self.google_team_groups[group]
                    logger.info(
                        "✅ FRESH DATA: Using current group data for group: %s (refreshed %ds ago)",
                        group,
                        int((now - last_refresh).total_seconds()),
                    )
                elif not force_refresh:
                    # We have data and we're not forcing refresh - use current data
                    stale_groups[group] = self.google_team_groups[group]
                    if last_refresh:
                        logger.warning(
                            "⚠️ STALE DATA: Using older group data for group: %s (refreshed %ds ago, interval %ds) - will not refresh on individual request",
                            group,
                            int((now - last_refresh).total_seconds()),
                            self.groups_refresh_interval,
                        )
                    else:
                        logger.warning(
                            "⚠️ STALE DATA: Using group data for group: %s (no timestamp) - will not refresh on individual request",
                            group,
                        )
                else:
                    # force_refresh=True and we have stale data - need to refresh
                    groups_to_refresh.append(group)
                    if last_refresh:
                        logger.info(
                            "🔄 FORCE REFRESH: Group %s data expired (%ds old, interval %ds), force refreshing",
                            group,
                            int((now - last_refresh).total_seconds()),
                            self.groups_refresh_interval,
                        )
                    else:
                        logger.info(
                            "🔄 FORCE REFRESH: Group %s has no timestamp, force refreshing",
                            group,
                        )
            else:
                # Group not in lookup at all
                groups_to_refresh.append(group)
                logger.info(
                    "❌ LOOKUP MISS: Group %s not in lookup, will refresh", group
                )

        # Combine fresh and stale data for the result
        result_from_current = {**current_groups, **stale_groups}

        # If all groups are available (fresh or stale), return the data
        if not groups_to_refresh:
            if current_groups and not stale_groups:
                logger.info(
                    "✅ ALL FRESH DATA: All requested groups found in fresh data: %s",
                    groups,
                )
            elif stale_groups and not current_groups:
                logger.info(
                    "⚠️ ALL STALE DATA: All requested groups found in stale data: %s",
                    groups,
                )
            else:
                logger.info(
                    "📋 MIXED DATA: Found %d fresh, %d stale groups from data: %s",
                    len(current_groups),
                    len(stale_groups),
                    groups,
                )
            return result_from_current

        # Copy current data (fresh + stale) to result
        result = dict(result_from_current)

        # Type guard to ensure google_team_groups is not None (initialized at startup)
        assert self.google_team_groups is not None, (
            "Groups dictionary should be initialized at startup"
        )

        try:
            # Ensure we have admin service
            if not self.admin_service or (self.expiration < now):
                self.__get_admin_service()

            # Type guard to ensure admin_service is not None
            assert self.admin_service is not None, "Admin service should be initialized"

            logger.info(
                "Refreshing Google Workspace group members for groups: %s",
                groups_to_refresh,
            )

            for group in groups_to_refresh:
                try:
                    # Get workspace domain from environment or extract from admin email
                    if not self.workspace_domain and "@" in self.impersonation_email:
                        self.workspace_domain = self.impersonation_email.split("@")[1]

                    group_key = (
                        f"{group}@{self.workspace_domain}"
                        if self.workspace_domain
                        else group
                    )
                    logger.debug("Fetching members for group: %s", group_key)

                    # Use type: ignore for Google API dynamic attributes
                    group_members = (
                        self.admin_service.members()
                        .list(groupKey=group_key)  # type: ignore[attr-defined]
                        .execute()
                        .get("members", [])
                    )

                    if group_members:
                        member_emails = [
                            member["email"]
                            for member in group_members
                            if "email" in member
                        ]
                        self.google_team_groups[group] = member_emails
                        result[group] = member_emails
                        logger.info(
                            "Found %d members in group %s", len(member_emails), group
                        )
                    else:
                        self.google_team_groups[group] = []
                        result[group] = []
                        logger.info("No members found in group %s", group)

                except Exception as group_error:
                    logger.warning(
                        "Failed to fetch members for group %s: %s", group, group_error
                    )
                    # Set empty list for failed groups to avoid repeated failures
                    self.google_team_groups[group] = []
                    result[group] = []

                # Update refresh timestamp for this individual group
                self.last_groups_refresh[group] = now

            if groups_to_refresh:
                logger.info(
                    "Successfully completed group member refresh for %d groups",
                    len(groups_to_refresh),
                )

        except Exception as e:
            logger.error("Error refreshing group members: %s", e)
            raise

        return result

    async def get_group_members(self, group: str, user: str) -> dict[str, bool]:
        """
        Public method to check if a user is part of a specific group.
        Uses cached data (even if stale) and only fetches if cache is completely empty.

        Args:
            group: Group name (without domain suffix)
            user: User email to check

        Returns:
            Dictionary with group name as key and boolean membership status as value
        """
        is_member = False

        # Ensure we have group data - only fetch if group is not in lookup
        if not self.google_team_groups or group not in self.google_team_groups:
            await self.__get_group_members([group])

        # Check membership using available data (fresh or stale)
        if (
            self.google_team_groups
            and group in self.google_team_groups
            and user in self.google_team_groups[group]
        ):
            is_member = True

        logger.debug("User %s membership in group %s: %s", user, group, is_member)
        return {group: is_member}

    async def check_user_groups(self, user: str, groups: list[str]) -> dict[str, bool]:
        """
        Check if a user is a member of multiple groups efficiently.
        Uses cached data (even if stale) to avoid triggering individual refreshes.

        Args:
            user: User email to check
            groups: List of group names (without domain suffix)

        Returns:
            Dictionary mapping group names to membership status
        """
        # Fetch group data (will use cache if available, even if stale)
        await self.__get_group_members(groups)

        result = {}
        for group in groups:
            is_member = False
            if (
                self.google_team_groups
                and group in self.google_team_groups
                and user in self.google_team_groups[group]
            ):
                is_member = True
            result[group] = is_member

        logger.info("User %s group membership check: %s", user, result)
        return result

    async def get_user_groups(self, user: str) -> list[str]:
        """
        Get all groups that a user belongs to from the currently cached groups.
        Note: This only checks groups that have been previously fetched.

        Args:
            user: User email to check

        Returns:
            List of group names the user belongs to
        """
        user_groups = []

        if self.google_team_groups:
            for group, members in self.google_team_groups.items():
                if user in members:
                    user_groups.append(group)

        logger.debug("User %s belongs to groups: %s", user, user_groups)
        return user_groups

    def clear_group_data(self, groups: list[str] | None = None) -> None:
        """
        Clear the group membership data for specific groups or all groups.

        Args:
            groups: List of group names to clear from data. If None, clears all group data.
        """
        if groups is None:
            # Clear all group data
            self.google_team_groups = None
            self.last_groups_refresh.clear()
            logger.info("Cleared all group data")
        else:
            # Clear specific groups from cache
            if self.google_team_groups:
                for group in groups:
                    self.google_team_groups.pop(group, None)

            # Clear refresh timestamps for these individual groups
            for group in groups:
                self.last_groups_refresh.pop(group, None)

            logger.info("Cleared group data for: %s", groups)

    async def validate_oauth_token_with_groups(
        self,
        access_token: str,
        required_groups: list[str] | None = None,
        require_all_groups: bool = False,
        org_unit_path: str | None = None,
        expected_client_id: str | None = None,
    ) -> ValidationResult:
        """
        Validate Google OAuth access token, check workspace membership, and optionally validate group membership.

        Args:
            access_token: OAuth access token to validate
            required_groups: List of groups the user must belong to (optional)
            require_all_groups: If True, user must belong to ALL groups. If False, user must belong to at least ONE group
            org_unit_path: Google Workspace organizational unit path. If None, uses default.
            expected_client_id: Expected OAuth client ID for validation

        Returns:
            ValidationResult with user info and validation status
        """
        # Use default org unit path if none provided
        if org_unit_path is None:
            org_unit_path = self.default_org_unit_path

        # First, perform standard OAuth and workspace validation
        standard_validation = await self.validate_oauth_token(
            access_token, org_unit_path, expected_client_id
        )

        if not standard_validation.is_valid or not standard_validation.user_info:
            return standard_validation

        # If no group requirements, return the standard validation
        if not required_groups:
            return standard_validation

        user_email = standard_validation.user_info.email

        # Check group membership
        try:
            group_membership = await self.check_user_groups(user_email, required_groups)

            # Determine if user meets group requirements
            groups_passed = [
                group for group, is_member in group_membership.items() if is_member
            ]

            if require_all_groups:
                # User must belong to ALL required groups
                groups_failed = [
                    group
                    for group in required_groups
                    if not group_membership.get(group, False)
                ]
                if groups_failed:
                    auth_logger.warning(
                        "User %s missing required groups: %s", user_email, groups_failed
                    )
                    return ValidationResult(
                        is_valid=False,
                        error_type="group_access_denied",
                        error_description=f"User does not belong to required groups: {', '.join(groups_failed)}",
                    )
            else:
                # User must belong to at least ONE required group
                if not groups_passed:
                    auth_logger.warning(
                        "User %s does not belong to any required groups: %s",
                        user_email,
                        required_groups,
                    )
                    return ValidationResult(
                        is_valid=False,
                        error_type="group_access_denied",
                        error_description=f"User does not belong to any of the required groups: {', '.join(required_groups)}",
                    )

            # Success: Update user info with group information
            enhanced_user = UserInfo(
                email=standard_validation.user_info.email,
                name=standard_validation.user_info.name,
                is_valid=True,
                permissions=standard_validation.user_info.permissions,
            )

            auth_logger.info(
                "User %s passed group validation. Groups: %s", user_email, groups_passed
            )

            return ValidationResult(user_info=enhanced_user, is_valid=True)

        except Exception as e:
            logger.error("Error during group validation for user %s: %s", user_email, e)
            return ValidationResult(
                is_valid=False,
                error_type="group_validation_error",
                error_description=f"Failed to validate group membership: {e!s}",
            )

    async def validate_oauth_token(
        self,
        access_token: str,
        org_unit_path: str | None = None,
        expected_client_id: str | None = None,
    ) -> ValidationResult:
        """Validate Google OAuth access token and check if user is in workspace."""

        # Use default org unit path if none provided
        if org_unit_path is None:
            org_unit_path = self.default_org_unit_path

        # First, validate the token with Google
        user_info: dict[str, Any] | None = None

        if expected_client_id:
            auth_logger.debug(
                "Validating OAuth token with client ID check: %s", expected_client_id
            )
            validation_result = await validate_google_oauth_token_with_client_check(
                access_token, expected_client_id
            )
            if not validation_result:
                logger.warning(
                    "OAuth token validation failed (invalid token or wrong client ID)"
                )
                return ValidationResult(
                    is_valid=False,
                    error_type="invalid_token",
                    error_description="Token validation failed",
                )

            # Check if validation failed due to client ID mismatch specifically
            if validation_result.get("client_mismatch"):
                auth_logger.warning(
                    "OAuth token client ID mismatch - signaling for DCR re-registration"
                )
                return ValidationResult(
                    is_valid=False,
                    error_type="invalid_client",
                    error_description="Token was not issued for the expected client ID",
                )

            user_info = validation_result.get("user_info")
            token_info = validation_result.get("token_info")

            if token_info:
                auth_logger.info(
                    "Token validated for client: %s, scope: %s",
                    token_info.get("audience"),
                    token_info.get("scope"),
                )
        else:
            # Standard validation without client ID check
            user_info = await validate_google_oauth_token(access_token)

        if not user_info:
            logger.warning("Invalid Google OAuth token")
            return ValidationResult(
                is_valid=False,
                error_type="invalid_token",
                error_description="Invalid or expired token",
            )

        user_email = user_info.get("email")
        if not user_email:
            logger.warning("No email in Google OAuth token response")
            return ValidationResult(
                is_valid=False,
                error_type="invalid_token",
                error_description="Token does not contain required email claim",
            )

        # Now check if this user is in our Google Workspace
        workspace_user = await self.__get_user(user_email, org_unit_path)
        if not workspace_user.is_valid:
            logger.warning(
                "User %s has valid Google token but is not in our workspace", user_email
            )
            return ValidationResult(
                is_valid=False,
                error_type="workspace_denied",
                error_description="User is not a member of the required Google Workspace",
            )

        # Success: Merge OAuth info with workspace info
        validated_user = UserInfo(
            email=user_email,
            name=user_info.get("name") or workspace_user.name,
            is_valid=True,
            permissions=["mcp:read", "mcp:write"],
        )

        return ValidationResult(user_info=validated_user, is_valid=True)


# Global instance - initialized lazily
_google_wif_config = None


def get_google_wif_config() -> GoogleWIF:
    """Get the global GoogleWIF instance, creating it if necessary."""
    global _google_wif_config
    if _google_wif_config is None:
        _google_wif_config = GoogleWIF()
    return _google_wif_config


class _LazyGoogleWIFConfig:
    """Lazy loader for GoogleWIF configuration that only initializes when accessed."""

    def __init__(self) -> None:
        self._instance: GoogleWIF | None = None

    def __getattr__(self, name: str) -> Any:
        """Lazy load the GoogleWIF instance when any attribute is accessed."""
        if self._instance is None:
            self._instance = GoogleWIF()
        return getattr(self._instance, name)

    def __bool__(self) -> bool:
        """Return True to indicate the config object exists."""
        return True


# For backward compatibility - this will be initialized on first access
google_wif_config = _LazyGoogleWIFConfig()
