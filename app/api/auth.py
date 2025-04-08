from fastapi import APIRouter, Depends, HTTPException, Header, Request
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import JSONResponse
from fastapi import status
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.crud.login_history import create_login_history
from app.schemas.user import UserCreate, UserOut
from app.schemas.token import Token
from app.crud.user import get_user_by_email, create_user
from app.services.redis import blacklist_token, is_token_blacklisted
from app.services.security import verify_password
from app.services.token import create_access_token, create_refresh_token, decode_token

router = APIRouter()



@router.post("/register", response_model=UserOut)
def register_user(user_in: UserCreate, db: Session = Depends(get_db)):
    user = create_user(db, user_in)
    if user:
        raise HTTPException(status_code=400, detail="Email already registered")
    return create_user(db, user_in)


@router.post("/login", response_model=Token)
def login_user(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    user = get_user_by_email(db, form_data.username)
    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(status_code=400, detail="Incorrect email or password")

    ip = request.client.host
    ua = request.headers.get("user-agent", "unknown")
    create_login_history(db, user.id, ip, ua)

    access_token = create_access_token(user.email)
    refresh_token = create_refresh_token(user.email)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }


@router.post("/refresh", response_model=Token)
def refresh_token(refresh_token: str = Header(...)):
    if is_token_blacklisted(refresh_token):
        raise HTTPException(status_code=401, detail="Token is blacklisted")

    subject = decode_token(refresh_token)
    if not subject:
        raise HTTPException(status_code=401, detail="Invalid token")

    access_token = create_access_token(subject)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }

@router.post("/logout")
def logout(refresh_token: str = Header(...)):
    subject = decode_token(refresh_token)
    if not subject:
        raise HTTPException(status_code=401, detail="Invalid token")

    # Assume 30 days in minutes = 43200
    blacklist_token(refresh_token, 60 * 43200)

    return JSONResponse(content={"detail": "Logged out successfully"})
