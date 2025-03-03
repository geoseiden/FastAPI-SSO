from datetime import timedelta
from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm
from authlib.integrations.starlette_client import OAuth, OAuthError
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from services.auth_service import authenticate_user, create_access_token,verify_token
from config import GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET
from db.database import get_db
from db.schemas import UserCreate, Token
from repo.user_repo import UserRepository
from db.models import User
from logger import logger

router = APIRouter()
templates = Jinja2Templates(directory="templates")

oauth = OAuth()
oauth.register(
    name="google",
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)


@router.get("/login", response_class=HTMLResponse)
async def login(request: Request):
    ip=request.client.host
    logger.info(f"IP : {ip} , Login page rendered")
    return templates.TemplateResponse("login.html", {"request": request})


@router.post("/login")
async def login_post(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    ip=request.client.host
    logger.info(f"IP: {ip} , Login process initiated")
    user_repo = UserRepository(db)
    user = authenticate_user(user_repo, email, password)
    if not user:
        logger.warning(f"IP: {ip} , Login halted(Invalid Email or Password)")
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid email or password"})

    access_token_expires = timedelta(hours=1)
    access_token = create_access_token(data={"sub": email}, expires_delta=access_token_expires)

    logger.info(f"IP: {ip} , Access token created and user redirected to dashboard")
    response = RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
    response.set_cookie(key="Authorization", value=f"Bearer {access_token}", httponly=True)
    return response

@router.get("/login/google")
async def login_with_google(request: Request):
    ip=request.client.host
    logger.info(f"IP: {ip} , Google login initiated")
    redirect_uri = request.url_for("google_callback")
    return await oauth.google.authorize_redirect(request, redirect_uri)

@router.get("/auth/google")
async def google_callback(request: Request, db: Session = Depends(get_db)):
    ip=request.client.host
    logger.info(f"IP: {ip} , Google callback recieved")
    user_repo = UserRepository(db)
    try:
        token = await oauth.google.authorize_access_token(request)
        user_info = token.get("userinfo")
        if not user_info:
            logger.warning(f"IP: {ip} , User info not available")
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User info not available")

        email = user_info["email"]
        user = user_repo.get_user_by_email(email)
        if not user:
            user_data = UserCreate(
                email=email,
                name=user_info.get("name"),
                hashed_password="google_oauth",
                role="user",
            )
            new_user = User(**user_data.dict())
            user = user_repo.create_user(new_user)

        access_token = create_access_token(data={"sub": email})
        logger.info(f"IP: {ip} , Access token created and redirected to dashboard")
        response = RedirectResponse(url="/dashboard")
        response.set_cookie(key="Authorization", value=f"Bearer {access_token}", httponly=True)
        return response
    except OAuthError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))


@router.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)
):
    user_repo = UserRepository(db)
    user = authenticate_user(user_repo, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(hours=1)
    access_token = create_access_token(data={"sub": form_data.username}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}


@router.get("/logout")
async def logout(request: Request):
    ip=request.client.host
    logger.info(f"IP : {ip} , Logged out")
    response = RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    response.delete_cookie("Authorization")
    return response
