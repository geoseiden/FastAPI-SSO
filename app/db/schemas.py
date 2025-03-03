from typing import List
from pydantic import BaseModel

class UserBase(BaseModel):
    id:str
    email: str
    name: str
    role: str
    disabled: bool

class UserCreate(UserBase):
    hashed_password: str

class UserInDB(UserBase):
    hashed_password: str

class UserOut(UserBase):
    pass

class Token(BaseModel):
    access_token: str
    token_type: str

class Roles(BaseModel):
    id: int
    role: str
    permissions: List[str]