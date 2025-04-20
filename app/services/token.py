from datetime import datetime, timedelta, timezone
from jose import JWTError, jwt
from app.configs.configs import settings
from app.utils.logs import get_logger

ALGORITHM = "HS256"

logger = get_logger(__name__)

def create_token(data: dict, expires_delta: int):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=expires_delta)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def create_access_token(subject: str):
    token = create_token({"sub": subject}, settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    logger.info(f"Created access token for subject: {token}")
    return token

def create_refresh_token(subject: str):
    refresh_token = create_token({"sub": subject}, settings.REFRESH_TOKEN_EXPIRE_MINUTES)
    logger.info(f"Created refresh token for subject: {refresh_token}")
    return refresh_token

def decode_token(token: str):
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM])
        logger.info(f"Decoded token payload: {payload}")
        if datetime.fromtimestamp(payload.get("exp"), tz=timezone.utc) < datetime.now(tz=timezone.utc):
            logger.error("Token has expired")
            return None
        return payload.get("sub")
    except JWTError:
        logger.error("Token decoding failed")
        return None
