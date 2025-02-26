from pydantic import BaseModel, EmailStr

class RoleBase(BaseModel):
    name: str
    email: EmailStr
    role: str

class RoleCreate(RoleBase):
    pass

class Role(RoleBase):
    id: int

    class Config:
        orm_mode: True

class UserBase(BaseModel):
    role: str
    permissions: str

class UserCreate(UserBase):
    pass

class User(UserBase):
    id: int

    class Config:
        orm_mode: True
