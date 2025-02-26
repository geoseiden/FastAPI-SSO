from fastapi import Depends, FastAPI, HTTPException, Request, Response
from starlette.responses import RedirectResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from database import engine, Base, get_db
from fastapi.security import HTTPBearer
from sqlalchemy.orm import Session
from dotenv import load_dotenv
from pydantic import BaseModel
import models, schemas, repos
from jose import jwt
import requests
import logging
import json
import os

load_dotenv()
server = FastAPI()
templates = Jinja2Templates(directory="templates")
Base.metadata.create_all(bind=engine)

jwks_url = str(os.getenv('AUTH0_URL')) + "/.well-known/jwks.json"
jwks_keys = requests.get(jwks_url).json()["keys"]
security = HTTPBearer()

logging.basicConfig(level=logging.INFO, filename="main.log", filemode="a",
                    format="%(asctime)s - %(levelname)s - %(message)s")

server.middleware("http") 
async def add_csp_headers(request: Request, call_next): 
    response = await call_next(request) 
    response.headers["Content-Security-Policy"] = ( "default-src 'self'; " "script-src 'self' 'https://cdn.jsdelivr.net' 'https://code.jquery.com'; " "style-src 'self' 'https://cdn.jsdelivr.net'; " "img-src 'self' data:; " "connect-src 'self'; " "font-src 'self' 'https://fonts.googleapis.com' 'https://fonts.gstatic.com'; " "frame-ancestors 'none'; " "object-src 'none'; " "script-src-elem 'self' 'https://cdn.jsdelivr.net' 'https://code.jquery.com'; " "style-src-elem 'self' 'https://cdn.jsdelivr.net';" ) 
    return response

def get_public_key(kid):
    for key in jwks_keys:
        if key["kid"] == kid:
            return key
    return None

def validate_token(token: str):
    try:
        unverified_header = jwt.get_unverified_header(token)
        public_key = get_public_key(unverified_header["kid"])
        if not public_key:
            logging.critical("Public Key not found in JWKS: HTTP Exception Raised: Status Code 401")
            raise HTTPException(status_code=401, detail="Public key not found.")
        
        decoded_token = jwt.decode(
            token,
            key=public_key,
            algorithms=["RS256"],
            audience="https://renol.com/orders/api",
        )
        return decoded_token
    except (jwt.JWTError, jwt.ExpiredSignatureError):
        logging.warning("Unauthenticated User: Redirected to Login: Status Code 302")
        raise HTTPException(status_code=302, detail="Not authenticated", headers={"Location": "/login"})

class User(BaseModel):
    sub: str
    permissions: list[str]

def get_current_user(request: Request, db: Session = Depends(get_db)):
    token = request.cookies.get("authToken")
    if not token:
        raise HTTPException(status_code=302, detail="Not authenticated", headers={"Location": "/login"})
    user_data = request.cookies.get("user")
    if not user_data:
        raise HTTPException(status_code=401, detail="User data not found", headers={"Location": "/login"})
    user = json.loads(user_data)
    return user

def verify_role(role: str):
    def role_dependency(request: Request, user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
        user_email = user.get("email")
        user_info = repos.get_user(db, user_email)
        
        user_role = repos.get_user_role(db, user_email)
        if user_role != role:
            logging.critical(f"User id {user_info.id} : Access forbidden ({request.url.path})")
            raise HTTPException(status_code=307, detail="Access forbidden: insufficient permissions",headers={"Location": "/login"})
    return role_dependency

@server.get("/login")
def login():
    logging.info("New Login initiated")
    return RedirectResponse(
        os.getenv('AUTH0_URL') + "/authorize"
        "?response_type=code"
        f"&client_id={os.getenv('AUTH0_CLIENT_ID')}"
        "&redirect_uri=http://localhost:8000/callback"
        "&scope=openid profile email"
        "&audience=https://renol.com/orders/api"
    )

@server.get("/callback")
def callback(request: Request, db: Session = Depends(get_db)):
    code = request.query_params.get("code")
    if not code:
        logging.critical("Authorization code not provided: HTTP Exception Raised: Status Code 400")
        return HTMLResponse("Authorization code not provided.", status_code=400)

    token_url = os.getenv('AUTH0_URL') + "/oauth/token"
    payload = {
        "grant_type": "authorization_code",
        "client_id": os.getenv("AUTH0_CLIENT_ID"),
        "client_secret": os.getenv("AUTH0_CLIENT_SECRET"),
        "code": code,
        "redirect_uri": "http://localhost:8000/callback"
    }
    headers = {"content-type": "application/x-www-form-urlencoded"}

    response = requests.post(token_url, data=payload, headers=headers)

    try:
        response.raise_for_status()
        token_data = response.json()

        if 'access_token' not in token_data:
            logging.critical("Access Token not found in Response: HTTP Exception Raised: Status Code 400" + json.dumps(token_data))
            return HTMLResponse(f"Error: 'access_token' not found in response - {json.dumps(token_data)}", status_code=400)

        userinfo_url = os.getenv('AUTH0_URL') + "/userinfo"
        userinfo_headers = {"Authorization": f"Bearer {token_data['access_token']}"}
        userinfo_response = requests.get(userinfo_url, headers=userinfo_headers)
        userinfo_data = userinfo_response.json()

        user_email = userinfo_data.get("email")
        user = repos.get_user(db, user_email)
        if user:
            logging.info(f"User logged in with ID: {user.id}")
            role = repos.get_user_role(db, user_email)
            if role == "admin":
                response = RedirectResponse("/admin")
            elif role == "L1":
                response = RedirectResponse("/employee")
            else:
                response = RedirectResponse("/denied_role")
        else:
            logging.warning(f"User with email {user_email} not found in the database.")
            response = RedirectResponse("/denied")

        response.set_cookie(key="authToken", value=token_data["access_token"], httponly=True, secure=True)
        response.set_cookie(key="user", value=json.dumps(userinfo_data), httponly=True, secure=True)
        return response
    except requests.exceptions.HTTPError as e:
        logging.critical(f"HTTP error occurred: {str(e)} - Response: {response.text} - Status Code: {response.status_code}")
        return HTMLResponse(f"HTTP error occurred: {str(e)}<br>Response: {response.text}", status_code=response.status_code)
    except Exception as e:
        logging.critical(f"An error occurred: {str(e)} - Status Code: 500")
        return HTMLResponse(f"An error occurred: {str(e)}", status_code=500)

@server.get("/admin", dependencies=[Depends(verify_role("admin"))])
def admin_dashboard(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    user_info = repos.get_user(db, user["email"])
    logging.info("Admin Login: User allowed access to admin dashboard")
    return templates.TemplateResponse("admin_dashboard.html", context={"request": request, "user": user_info})

@server.get("/employee", dependencies=[Depends(verify_role("L1"))])
def l1_dashboard(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    user_info = repos.get_user(db, user["email"])
    logging.info("Employee Login: User allowed access to employee dashboard")
    return templates.TemplateResponse("employee_dashboard.html", context={"request": request, "user": user_info})

@server.get("/denied")
def denied(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if user:
        user_info = repos.get_user(db, user["email"])
        if user_info:
            logging.critical(f"User Access Denied: User {user_info.id} Redirected to Access denied page: Status Code 302")
    else:
        logging.critical("User Access Denied: No user information found")
    return templates.TemplateResponse("denied.html", context={"request": request})

@server.get("/denied_role")
def denied_role(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if user:
        user_info = repos.get_user(db, user["email"])
        if user_info:
            logging.critical(f"User Access Denied: User {user_info.id} Not assigned any Role Redirected to Access denied page : Status Code 302")
    else:
        logging.critical("User Access Denied: No roles assigned for user")
    return templates.TemplateResponse("denied_role.html", context={"request": request,"user_info":user_info})

@server.get("/logout")
def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    user_data = request.cookies.get("user")
    if user_data:
        user_info = json.loads(user_data)
        user_email = user_info.get("email")
        user = repos.get_user(db, user_email)
        if user:
            logging.warning(f"User id {user.id} : Logged out")
        else:
            logging.warning(f"User with email {user_email} not found in the database.")
    else:
        logging.warning("No user data found in cookies.")

    response = RedirectResponse(f"{os.getenv('AUTH0_URL')}/v2/logout?returnTo=http://localhost:8000/login")
    response.delete_cookie("authToken", secure=True, httponly=True)
    response.delete_cookie("user", secure=True, httponly=True)
    return response
