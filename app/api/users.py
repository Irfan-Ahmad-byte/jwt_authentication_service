from fastapi import APIRouter, Depends, Header
from app.core.database import get_db
from app.crud.login_history import get_user_login_history
from app.crud.user import get_user_by_email
from app.schemas.login_history import LoginHistoryOut
from app.schemas.user import UserOut
from app.services.token import decode_token
from app.services.redis import is_token_blacklisted
from fastapi.security import OAuth2PasswordBearer
from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.utils.logs import get_logger

logger = get_logger(__name__)
router = APIRouter()

@router.get("/me", response_model=UserOut)
def get_me(token: str = Header(...), db: Session = Depends(get_db)):
    token = token.replace("Bearer ", "")
    logger.info(f"Token: {token}")
    if not token:
        logger.error("Token is missing")
        raise HTTPException(status_code=401, detail="Token is missing")
    
    if is_token_blacklisted(token):
        logger.error("Token is blacklisted")
        raise HTTPException(status_code=401, detail="Token is blacklisted")

    subject = decode_token(token)
    if not subject:
        logger.error("Invalid token")
        raise HTTPException(status_code=401, detail="Invalid token")

    user = get_user_by_email(db, subject)
    if not user:
        logger.error("User not found")
        raise HTTPException(status_code=404, detail="User not found")

    return user

@router.get("/login-history", response_model=list[LoginHistoryOut])
def login_history(token: str = Header(...), db: Session = Depends(get_db)):
    token = token.replace("Bearer ", "")
    if is_token_blacklisted(token):
        logger.error("Token is blacklisted")
        raise HTTPException(status_code=401, detail="Token is blacklisted")

    subject = decode_token(token)
    if not subject:
        logger.error("Invalid token")
        raise HTTPException(status_code=401, detail="Invalid token")

    user = get_user_by_email(db, subject)
    if not user:
        logger.error("User not found")
        raise HTTPException(status_code=404, detail="User not found")

    return get_user_login_history(db, user.id)
