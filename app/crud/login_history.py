from sqlalchemy.orm import Session
from app.models.login_history import LoginHistory

def create_login_history(db: Session, user_id: int, ip: str, ua: str):
    history = LoginHistory(user_id=user_id, ip_address=ip, user_agent=ua)
    db.add(history)
    db.commit()

def get_user_login_history(db: Session, user_id: int):
    return db.query(LoginHistory).filter(LoginHistory.user_id == user_id).order_by(LoginHistory.timestamp.desc()).all()
