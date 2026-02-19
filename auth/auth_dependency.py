from fastapi.security import HTTPAuthorizationCredentials,HTTPBearer
from fastapi import Depends,HTTPException,status
from auth.jwt_handler import verify_token

security=HTTPBearer()

def get_current_user(creadentials:HTTPAuthorizationCredentials=Depends(security)):
    token=creadentials.credentials
    payload=verify_token(token)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return payload