from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, Request, status
import jwt

from config import ALGORITHM, SECRET_KEY
from db.models import User
from db.schemas import UserOut
from db.database import get_db
from repo.user_repo import UserRepository,RolesRepository
from logger import logger

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def authenticate_user(user_repo: UserRepository, email: str, password: str) -> User:
    user = user_repo.get_user_by_email(email)
    if not user:
        return None

    if not pwd_context.verify(password, user.hashed_password):
        return None
    return user

def has_permissions(request: Request, current_user_role: str, db: Session=Depends(get_db)):
    role_repo=RolesRepository(db)

    if not role_repo.check_role(current_user_role):
        ip=request.client.host
        logger.warning(f"IP: {ip} , has_permissions() : User role not found")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User role not found",
        )

    permissions = role_repo.get_permissions(current_user_role).permissions

    if request.url.path not in permissions:
        ip=request.client.host
        logger.warning(f"IP: {ip} , has_permissions() : Access Denied, permission not granted")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied. Permission not granted.",
        )

    return True

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_token_from_cookie(request: Request) -> str:
    ip=request.client.host
    token = request.cookies.get("Authorization")
    if not token:
        logger.warning(f"IP: {ip} , get_token_from_cookie() : User role not authenticated")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if token.startswith("Bearer "):
        token = token[len("Bearer "):]
    return token

def verify_token(request:Request,token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        ip=request.client.host
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        user_repo=UserRepository(db)

        if email is None:
            logger.warning(f"IP: {ip} , verify_token() : Email not found")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token. Email not found.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        user = user_repo.get_user_by_email(email)
        if user is None:
            logger.warning(f"IP: {ip} , verify_token() : User not found")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if user.disabled==1:
            logger.warning(f"IP: {ip} , verify_token() : User has been disabled")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User is currently disabled",
                headers={"WWW-Authenticate": "Bearer"},
            )

        logger.warning(f"IP: {ip} , verify_token() : Token Verified")
        return UserOut(id=user.id,email=user.email,name=user.name,disabled=user.disabled,role=user.role)

    except jwt.ExpiredSignatureError:
        logger.warning(f"IP: {ip} , verify_token() : Token expired and redirected to login")
        raise HTTPException(
            status_code=302,
            detail="Token has expired. Please log in again.",
            headers={"WWW-Authenticate": "Bearer","Location": "/login"},
        )