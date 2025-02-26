from sqlalchemy.orm import Session
import models

def get_user_role(db: Session, user_email: str):
    user = db.query(models.Users).filter(models.Users.email == user_email).first()
    if user:
        return user.role
    return None

def get_user(db:Session, user_email:str):
    user = db.query(models.Users).filter(models.Users.email == user_email).first()
    return user