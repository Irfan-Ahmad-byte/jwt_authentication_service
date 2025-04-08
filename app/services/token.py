from datetime import datetime, timedelta, timezone
from jose import JWTError, jwt
from app.configs.configs import settings

ALGORITHM = "HS256"

def create_token(data: dict, expires_delta: int):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=expires_delta)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def create_access_token(subject: str):
    return create_token({"sub": subject}, settings.ACCESS_TOKEN_EXPIRE_MINUTES)

def create_refresh_token(subject: str):
    return create_token({"sub": subject}, settings.REFRESH_TOKEN_EXPIRE_MINUTES)

def decode_token(token: str):
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("sub")
    except JWTError:
        return None
