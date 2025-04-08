from app.configs.configs import settings
from app.utils.logs import get_logger

logger = get_logger(__name__)


def check_redis_connection():
    """
    Check the Redis connection.
    """
    try:
        from redis import Redis
        redis_client = Redis.from_url(settings.REDIS_URL, decode_responses=True)
        redis_client.ping()
        logger.info("Redis connection successful.")
        return redis_client
    except Exception as e:
        logger.error(f"Redis connection failed: {e}")
        settings.IS_REDIS_RUNNING = False
        raise e
    
def close_redis_connection(client):
    """
    Close the Redis connection.
    """
    try:
        client.close()
        logger.info("Redis connection closed.")
    except Exception as e:
        logger.error(f"Failed to close Redis connection: {e}")