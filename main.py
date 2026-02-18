
from fastapi import FastAPI, HTTPException
from db.database import get_client, get_db
from routers.medicine import router as medicine_router
from routers.auth import router as auth_router
app = FastAPI(title="Medicine API", description="API for managing medicines in MongoDB", version="1.0.0")
app.include_router(medicine_router)
app.include_router(auth_router)

@app.get("/")
def check_connection():
    try:
        get_client().admin.command("ping")
        collections = get_db().list_collection_names()
        return {
            "status": "Connected successfully",
            "database": get_db().name,
            "collections": collections
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
    
