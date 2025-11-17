"""
Token Blacklist/Revocation Management

Manages revoked JWT tokens using Redis for fast lookup.
Tokens are blacklisted on logout or when compromised.
"""

from typing import Optional
from datetime import datetime, timedelta
from redis import Redis
import logging

logger = logging.getLogger(__name__)


class TokenBlacklist:
    """
    Manages blacklisted/revoked JWT tokens using Redis

    Architecture:
    - Uses Redis SET with TTL for automatic cleanup
    - Key format: "token:blacklist:{jti}"
    - TTL matches token expiration time
    - Fast O(1) lookup performance
    """

    def __init__(self, redis_url: str = "redis://localhost:6379/0"):
        """
        Initialize token blacklist

        Args:
            redis_url: Redis connection URL
        """
        self.redis = Redis.from_url(redis_url, decode_responses=True)
        self.prefix = "token:blacklist:"

        # Test connection
        try:
            self.redis.ping()
            logger.info("Token blacklist initialized successfully")
        except Exception as e:
            logger.error(f"Failed to connect to Redis for token blacklist: {e}")
            raise

    def blacklist_token(
        self,
        jti: str,
        expires_at: datetime,
        reason: str = "logout"
    ) -> bool:
        """
        Blacklist a token

        Args:
            jti: JWT Token ID (from token claims)
            expires_at: When the token expires
            reason: Reason for blacklisting (logout, compromised, etc.)

        Returns:
            True if successfully blacklisted
        """
        try:
            key = f"{self.prefix}{jti}"

            # Calculate TTL (time until token expires)
            now = datetime.utcnow()
            ttl_seconds = int((expires_at - now).total_seconds())

            # Only blacklist if token hasn't already expired
            if ttl_seconds > 0:
                # Store with metadata
                value = f"{reason}|{datetime.utcnow().isoformat()}"

                # Set with TTL - auto-deletes when token would have expired anyway
                self.redis.setex(key, ttl_seconds, value)

                logger.info(f"Token {jti[:8]}... blacklisted (reason: {reason}, TTL: {ttl_seconds}s)")
                return True
            else:
                logger.debug(f"Token {jti[:8]}... already expired, not blacklisting")
                return False

        except Exception as e:
            logger.error(f"Failed to blacklist token {jti[:8]}...: {e}")
            return False

    def is_blacklisted(self, jti: str) -> bool:
        """
        Check if a token is blacklisted

        Args:
            jti: JWT Token ID

        Returns:
            True if token is blacklisted
        """
        try:
            key = f"{self.prefix}{jti}"
            exists = self.redis.exists(key)

            if exists:
                logger.warning(f"Blacklisted token {jti[:8]}... attempted use")

            return bool(exists)

        except Exception as e:
            logger.error(f"Failed to check token blacklist for {jti[:8]}...: {e}")
            # Fail secure - treat as blacklisted if we can't check
            return True

    def remove_from_blacklist(self, jti: str) -> bool:
        """
        Remove a token from blacklist (rarely used)

        Args:
            jti: JWT Token ID

        Returns:
            True if successfully removed
        """
        try:
            key = f"{self.prefix}{jti}"
            deleted = self.redis.delete(key)

            if deleted:
                logger.info(f"Token {jti[:8]}... removed from blacklist")

            return bool(deleted)

        except Exception as e:
            logger.error(f"Failed to remove token {jti[:8]}... from blacklist: {e}")
            return False

    def get_blacklist_info(self, jti: str) -> Optional[dict]:
        """
        Get information about a blacklisted token

        Args:
            jti: JWT Token ID

        Returns:
            Dictionary with blacklist info or None
        """
        try:
            key = f"{self.prefix}{jti}"
            value = self.redis.get(key)

            if value:
                reason, timestamp = value.split("|", 1)
                ttl = self.redis.ttl(key)

                return {
                    "jti": jti,
                    "reason": reason,
                    "blacklisted_at": timestamp,
                    "expires_in_seconds": ttl
                }

            return None

        except Exception as e:
            logger.error(f"Failed to get blacklist info for {jti[:8]}...: {e}")
            return None

    def blacklist_user_tokens(self, user_id: str, reason: str = "security"):
        """
        Blacklist all tokens for a specific user
        This requires storing user_id->jti mappings

        Args:
            user_id: User ID
            reason: Reason for blacklisting

        Note: Requires additional user_tokens tracking
        """
        # TODO: Implement user token tracking if needed
        logger.warning("blacklist_user_tokens not fully implemented yet")
        pass

    def get_stats(self) -> dict:
        """
        Get blacklist statistics

        Returns:
            Dictionary with stats
        """
        try:
            # Count blacklisted tokens
            pattern = f"{self.prefix}*"
            keys = self.redis.keys(pattern)

            return {
                "total_blacklisted": len(keys),
                "prefix": self.prefix
            }

        except Exception as e:
            logger.error(f"Failed to get blacklist stats: {e}")
            return {"error": str(e)}

    def cleanup_expired(self) -> int:
        """
        Manual cleanup of expired tokens (Redis TTL should handle this automatically)

        Returns:
            Number of tokens cleaned up
        """
        # Redis TTL handles this automatically, but we can force cleanup if needed
        logger.debug("Redis TTL handles automatic cleanup")
        return 0


# Global instance
_blacklist_instance: Optional[TokenBlacklist] = None


def get_token_blacklist(redis_url: str = None) -> TokenBlacklist:
    """
    Get global token blacklist instance (singleton)

    Args:
        redis_url: Redis URL (only used on first call)

    Returns:
        TokenBlacklist instance
    """
    global _blacklist_instance

    if _blacklist_instance is None:
        from gtl_api_gateway.config import settings
        url = redis_url or settings.REDIS_URL
        _blacklist_instance = TokenBlacklist(url)

    return _blacklist_instance


# Convenience functions

def blacklist_token(jti: str, expires_at: datetime, reason: str = "logout") -> bool:
    """Convenience function to blacklist a token"""
    blacklist = get_token_blacklist()
    return blacklist.blacklist_token(jti, expires_at, reason)


def is_token_blacklisted(jti: str) -> bool:
    """Convenience function to check if token is blacklisted"""
    blacklist = get_token_blacklist()
    return blacklist.is_blacklisted(jti)
