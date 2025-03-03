from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware

from config import SECRET_KEY
from routes import auth_routes
from routes import user_routes
from logger import logger

app = FastAPI()
logger.info("FastAPI server has started")
app.include_router(auth_routes.router)
app.include_router(user_routes.router)
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)