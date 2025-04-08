from pydantic import BaseModel
from datetime import datetime

class LoginHistoryOut(BaseModel):
    ip_address: str
    user_agent: str
    timestamp: datetime

    class Config:
        orm_mode = True
