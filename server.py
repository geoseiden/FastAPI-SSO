from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.security import HTTPBearer
from jose import jwt
import requests
from starlette.responses import RedirectResponse, HTMLResponse
from pydantic import BaseModel
import json
import os
from dotenv import load_dotenv

load_dotenv()

server = FastAPI()

jwks_url = str(os.getenv('AUTH0_URL') )+ "/.well-known/jwks.json"
jwks_keys = requests.get(jwks_url).json()["keys"]

security = HTTPBearer()

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
            raise HTTPException(status_code=401, detail="Public key not found.")
        
        decoded_token = jwt.decode(
            token,
            key=public_key,
            algorithms=["RS256"],
            # The below website is meant to be fictional
            audience="https://renol.com/orders/api",
        )
        return decoded_token
    except (jwt.JWTError, jwt.ExpiredSignatureError):
        raise HTTPException(status_code=401, detail="Invalid token.")

class User(BaseModel):
    sub: str
    permissions: list[str]

@server.get("/login")
def login():
    return RedirectResponse(
        os.getenv('AUTH0_URL') + "/authorize"
        "?response_type=code"
        f"&client_id={os.getenv('CLIENT_ID')}"
        "&redirect_uri=http://localhost:8000/callback"
        "&scope=openid profile email"
        # The below website is meant to be fictional
        "&audience=https://renol.com/orders/api"
    )

@server.get("/callback")
def callback(request: Request):
    code = request.query_params.get("code")
    if not code:
        return HTMLResponse("Authorization code not provided.", status_code=400)

    token_url = os.getenv('AUTH0_URL') + "/oauth/token"
    payload = {
        "grant_type": "authorization_code",
        "client_id": os.getenv("CLIENT_ID"),
        "client_secret": os.getenv("CLIENT_SECRET"),  # Use environment variable
        "code": code,
        "redirect_uri": "http://localhost:8000/callback"
    }
    headers = {"content-type": "application/x-www-form-urlencoded"}

    response = requests.post(token_url, data=payload, headers=headers)

    try:
        response.raise_for_status()
        token_data = response.json()

        if 'access_token' not in token_data:
            return HTMLResponse(f"Error: 'access_token' not found in response - {json.dumps(token_data)}", status_code=400)

        response = RedirectResponse("/job-check")
        response.set_cookie(key="authToken", value=token_data["access_token"], httponly=True)
        return response
    except requests.exceptions.HTTPError as e:
        print("HTTP error occurred:", str(e))
        print("Response:", response.text)
        return HTMLResponse(f"HTTP error occurred: {str(e)}<br>Response: {response.text}", status_code=response.status_code)
    except Exception as e:
        print("An error occurred:", str(e))
        return HTMLResponse(f"An error occurred: {str(e)}", status_code=500)

def get_token_from_cookie(request: Request) -> str:
    token = request.cookies.get("authToken")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return token

@server.get("/dashboard")
def dashboard(request: Request):
    token = get_token_from_cookie(request)
    user_claims = validate_token(token)
    return HTMLResponse(f"""
        <html>
        <body>
            <h1>Welcome to the Dashboard</h1>
            <p>You are successfully authorized!</p>
            <p>User ID: {user_claims['sub']}</p>
            <p>Permissions: {', '.join(user_claims['permissions'])}</p>
        </body>
        </html>
    """)

@server.get("/job-check")
def new_protected_endpoint(request: Request):
    token = get_token_from_cookie(request)
    user_claims = validate_token(token)
    return HTMLResponse(f"""
        <html>
        <body>
            //Target address for showing after login
            <embed src="https://www.home.jobcheck.in/" width=100% height=100%>
        </body>
        </html>
    """)

@server.get("/logout")
def logout(response: Response):
    response = HTMLResponse("<p>Logged out successfully.</p>")
    response.delete_cookie("authToken")
    return response
