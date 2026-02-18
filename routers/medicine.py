from fastapi import HTTPException, Path,APIRouter
from fastapi.responses import JSONResponse
from models.Medicine import Medicine
from db.database import get_medicine_collection

medicine_collection= get_medicine_collection()
router=APIRouter(prefix="/medicine", tags=["Medicine"])

@router.get("")
def get_medicines():
    try:
        medicines_cursor= medicine_collection.find()
        medicines_list = []
        for med in medicines_cursor:
            med["_id"] = str(med["_id"])
            medicines_list.append(med)
        return JSONResponse(status_code=200,content={"medicines": medicines_list})
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
@router.get("/{medicine_id}")
def get_medicine(medicine_id: str=Path(..., description="The ID of the medicine to retrieve")):
    try:
        medicine=medicine_collection.find_one({"id": medicine_id})
        if not medicine:
            raise HTTPException(status_code=404, detail="Medicine not found")
        medicine["_id"]= str(medicine["_id"])
        return JSONResponse(status_code=200,content={"medicine": medicine})
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
@router.delete("/{medicine_id}")
def delete_medicine(medicine_id:str):
    try:
        result = medicine_collection.delete_one({"id": medicine_id})
        if result.deleted_count==0:
            raise HTTPException(status_code=404, detail="medicine not found")
        return JSONResponse(status_code=204, content={"message": "medicine deleted successfully"})
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
@router.put("/{medicine_id}")
def update_medicine(medicine_id: str, updated_medicine: Medicine):
    try:
        existing = medicine_collection.find_one({"id": medicine_id})
        if not existing:
            raise HTTPException(status_code=404, detail="Medicine not found")
        update_data = updated_medicine.model_dump()
        update_data.pop("id", None)
        medicine_collection.update_one({"id": medicine_id},{"$set": update_data})
        return JSONResponse(
            status_code=204,
            content={"message": "Medicine updated successfully"}
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
@router.post("")
def add_medicine(medicine: Medicine):
    try:
        if medicine_collection.find_one({"id": medicine.id}):
            raise HTTPException(status_code=400, detail="Medicine with this ID already exists")
        medicine_collection.insert_one(medicine.model_dump())
        return JSONResponse(
            status_code=201,
            content={"message": "Medicine added successfully", "medicine": medicine.model_dump()}
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to add medicine")