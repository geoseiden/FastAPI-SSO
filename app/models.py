from sqlalchemy import *
from database   import *

class Users(Base):
    __tablename__ = "users"

    id=Column(String(5),index=True,unique=True,nullable=False)
    name=Column(String(40),nullable=False)
    email=Column(String(25),unique=True,nullable=False,primary_key=True)
    role=Column(String(10),nullable=False)

class roles(Base):
    __tablename__ = "roles"

    id=Column(Integer,index=True,unique=True,nullable=False,primary_key=True)
    role=Column(String(10),unique=True,nullable=False)
    permissions=Column(String(255),nullable=False)