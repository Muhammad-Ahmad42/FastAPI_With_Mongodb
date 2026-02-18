from fastapi import APIRouter, HTTPException,Depends
from db.database import get_user_collection
from models.User import User
from auth.password_handler import hash_password,verify_password
from auth.jwt_handler import create_access_token

router=APIRouter(prefix="/auth", tags=["auth"])

@router.post("/register")
async def register(user:User, user_collection=Depends(get_user_collection)):
    existing_user=user_collection.find_one({"email": user.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")
    hashed=hash_password(user.password)
    user_collection.insert_one({"email": user.email, "password": hashed})
    return {"message": "User registered successfully"}

@router.post("/login")
async def login(user:User, user_colletion=Depends(get_user_collection)):
    existing_user=user_colletion.find_one({"email":user.email})
    if not existing_user:
        raise HTTPException(status_code=400, detail="Invalid email")
    if not verify_password(user.password, existing_user["password"]):
        raise HTTPException(status_code=401, detail="Invalid password")
    token = create_access_token({"sub": user.email})
    return {
        "access_token": token,
        "token_type": "bearer"
    }

    