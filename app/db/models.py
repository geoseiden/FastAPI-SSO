from sqlalchemy.ext.declarative import as_declarative, declared_attr
from sqlalchemy import JSON, TIMESTAMP,Column, String, Boolean, Integer, func
from db.database import Base,engine

@as_declarative()
class Base:
    @declared_attr
    def __tablename__(cls):
        return cls.__name__.lower()

    created_at = Column(TIMESTAMP, default=func.now(), nullable=False)
    updated_at = Column(TIMESTAMP, default=func.now(), onupdate=func.now(), nullable=False)

class User(Base):
    __tablename__ = "users"
    id = Column(String(5), unique=True, index=True)
    name = Column(String(40), nullable=False)
    email = Column(String(25), primary_key=True, index=True)
    role = Column(String(10))
    disabled = Column(Boolean, nullable=False)
    hashed_password = Column(String(70), nullable=False)

class Roles(Base):
    __tablename__ = "roles"
    id=Column(Integer,unique=True,index=True,primary_key=True)
    role=Column(String(10))
    permissions = Column(JSON, nullable=False, default=[])

class Veruthe(Base):
    __tablename__ ="veruthe"
    id=Column(Integer,index=True,primary_key=True)


Base.metadata.create_all(bind=engine)