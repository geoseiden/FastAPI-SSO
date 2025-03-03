from fastapi import APIRouter, Depends, Form, Request, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from services.auth_service import get_token_from_cookie, has_permissions, verify_token, pwd_context
from db.schemas import UserOut
from db.models import User
from db.database import get_db
from repo.user_repo import UserRepository
from logger import logger

router = APIRouter()
templates = Jinja2Templates(directory="templates")

@router.get("/user", response_model=UserOut)
async def get_user_data(
    db: Session = Depends(get_db),
    token: str = Depends(get_token_from_cookie),
    request: Request = None
):
    ip=request.client.host
    current_user = verify_token(request,token=token, db=db)
    logger.info(f"IP: {ip} , User : {current_user.id}({current_user.role}) , /user:Requested user information")
    has_permissions(request=request, current_user_role=current_user.role, db=db)
    return UserOut(
        id=current_user.id, email=current_user.email, name=current_user.name,disabled=current_user.disabled, role=current_user.role
    )

@router.get("/users", response_model=list[UserOut])
async def get_all_users(
    db: Session = Depends(get_db),
    token: str = Depends(get_token_from_cookie),
    request: Request = None
):
    ip=request.client.host
    user_repo = UserRepository(db)
    current_user = verify_token(request,token=token, db=db)
    has_permissions(request,current_user.role,db)


    logger.info(f"IP: {ip} , User : {current_user.id}({current_user.role}) , /users:Requested all users information")
    users = user_repo.get_all_users()
    return [UserOut(id=user.id, email=user.email, name=user.name,disabled=user.disabled, role=user.role) for user in users]

@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    db: Session = Depends(get_db),
    token: str = Depends(get_token_from_cookie)
):
    
    ip=request.client.host
    user_repo = UserRepository(db)
    current_user = verify_token(request,token, db)
    logger.info(f"IP: {ip} , User : {current_user.id}({current_user.role}) , /dashboard")
    return templates.TemplateResponse("dashboard.html", {"request": request, "user": current_user})

@router.post("/register")
async def register_user(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    name: str = Form(...),
    db: Session = Depends(get_db)
):
    user_repo = UserRepository(db)
    generated_id = "FM" + str(user_repo.count_users() + 1).zfill(3)
    new_user = User(
        id=generated_id,
        name=name,
        email=email,
        hashed_password=pwd_context.hash(password),
        role="",
        disabled=True
    )
    user_repo.create_user(new_user)
    ip=request.client.host
    logger.info(f"IP: {ip} , User : {new_user.id} , /register : New user registered")
    return {"message": "User Registered Successfully", "ID": new_user.id, "Name": new_user.name}

@router.post("/register_role")
async def register_role(
    request: Request,
    id: str = Form(...),
    role: str = Form(...),
    db: Session = Depends(get_db),
    token: str = Depends(get_token_from_cookie)
):
    user_repo = UserRepository(db)
    current_user = verify_token(request,token, db)
    has_permissions(request, current_user.role, db)

    user = user_repo.get_user_by_id(id)
    if not user:      
        ip=request.client.host
        logger.warning(f"IP: {ip} , User : {user.id} , /register_role : User not found")
        return {"Message": "User Not Found"}

    user.role = role
    if role is not None:
        user.disabled = False
    user_repo.update_user(user)

    ip=request.client.host
    logger.warning(f"IP: {ip} , User : {user.id} , /register_role : User role updated to {role} by {current_user.id}")

    return {"message": "User Role Registered Successfully", "ID": user.id, "role": user.role}

@router.post("/update_users")
async def update_users(
    request: Request,
    id: str = Form(...),
    name: str = Form(...),
    email: str = Form(...),
    db: Session = Depends(get_db),
    token: str = Depends(get_token_from_cookie)
):
    user_repo = UserRepository(db)
    current_user = verify_token(request,token, db)
    has_permissions(request, current_user.role, db)

    user = user_repo.get_user_by_id(id)
    if not user:
        ip=request.client.host
        logger.warning(f"IP: {ip} , User : {user.id} , /update_users : User not found")
        return {"Message": "User Not Found"}

    user.name = name
    user.email = email
    user_repo.update_user(user)

    ip=request.client.host
    logger.info(f"IP: {ip} , User : {user.id} , /update_users : User updated successfully by {current_user.id}")

    return {"message": "User Updated Successfully", "ID": user.id, "Name": user.name}

@router.post("/disable_user")
async def update_users(
    request: Request,
    id: str = Form(...),
    db: Session = Depends(get_db),
    token: str = Depends(get_token_from_cookie)
):
    user_repo = UserRepository(db)
    current_user = verify_token(request,token, db)
    has_permissions(request, current_user.role, db)

    user = user_repo.get_user_by_id(id)
    if not user:
        ip=request.client.host
        logger.warning(f"IP: {ip} , User : {user.id} , /disable_user : User not found")
        return {"Message": "User Not Found"}

    ip=request.client.host
    if user.disabled==True:
        logger.critical(f"IP: {ip} , User : {user.id} , /disable_user : User enabled by {current_user.id}")
        user_repo.enable_user(id)
        return {"message": "User Enabled Successfully", "ID": user.id, "Name": user.name}
    elif user.disabled==False:
        logger.critical(f"IP: {ip} , User : {user.id} , /disable_user : User disabled by {current_user.id}")
        user_repo.disable_user(id)
        return {"message": "User Disabled Successfully", "ID": user.id, "Name": user.name}



@router.post("/delete_user")
async def delete_users(
    request: Request,
    id: str = Form(...),
    db: Session = Depends(get_db),
    token: str = Depends(get_token_from_cookie)
):
    user_repo = UserRepository(db)
    current_user = verify_token(request,token, db)
    has_permissions(request, current_user.role, db)

    user = user_repo.get_user_by_id(id)
    if not user:
        ip=request.client.host
        logger.warning(f"IP: {ip} , User : {user.id} , /delete_user : User not found")
        return {"Message": "User Not Found"}

    user_repo.delete_user(user)
    ip=request.client.host
    logger.critical(f"IP: {ip} , User : {user.id} , /delete_user : User deleted by {current_user.id}")
    return JSONResponse(status_code=status.HTTP_200_OK, content={"message": "User deleted successfully"})