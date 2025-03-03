from sqlalchemy.orm import Session
from db.models import User,Roles

class UserRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_user_by_email(self, email: str) -> User:
        return self.db.query(User).filter(User.email == email).first()

    def get_user_by_id(self, user_id: str) -> User:
        return self.db.query(User).filter(User.id == user_id).first()

    def get_all_users(self) -> list[User]:
        return self.db.query(User).all()

    def create_user(self, user: User) -> User:
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        return user

    def update_user(self, user: User) -> User:
        self.db.commit()
        self.db.refresh(user)
        return user

    def delete_user(self, user: User):
        self.db.delete(user)
        self.db.commit()

    def count_users(self):
        return self.db.query(User).count()
    
    def disable_user(self,user_id : str):
        user=self.db.query(User).filter(User.id==user_id).first()
        user.dsiabled=1
        user.role=""

        self.db.commit()
        self.db.refresh(user)

    def enable_user(self,user_id : str):
        user=self.db.query(User).filter(User.id==user_id).first()
        user.disabled=0
        user.role=""

        self.db.commit()
        self.db.refresh(user)

class RolesRepository:
    def __init__(self,db:Session):
        self.db=db

    def get_permissions(self, user_role) -> Roles:
        return self.db.query(Roles).filter(Roles.role == user_role).first()
    
    def check_role(self, user_role: str) -> bool:
        return self.db.query(Roles).filter(Roles.role == user_role).first() is not None