from fastapi import APIRouter, Depends
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


router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

@router.get("/me", response_model=UserOut)
def get_me(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    if is_token_blacklisted(token):
        raise HTTPException(status_code=401, detail="Token is blacklisted")

    subject = decode_token(token)
    if not subject:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = get_user_by_email(db, subject)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return user

@router.get("/login-history", response_model=list[LoginHistoryOut])
def login_history(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    if is_token_blacklisted(token):
        raise HTTPException(status_code=401, detail="Token is blacklisted")

    subject = decode_token(token)
    if not subject:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = get_user_by_email(db, subject)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return get_user_login_history(db, user.id)