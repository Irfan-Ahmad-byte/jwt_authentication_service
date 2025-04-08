from app.core.redis import check_redis_connection


r = check_redis_connection()

def blacklist_token(token: str, expires_in: int):
    r.setex(f"blacklist:{token}", expires_in, "true")

def is_token_blacklisted(token: str) -> bool:
    return r.exists(f"blacklist:{token}") == 1
