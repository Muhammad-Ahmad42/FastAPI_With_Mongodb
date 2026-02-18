
from pydantic import BaseModel, Field
class Medicine(BaseModel):
    id: str
    name: str
    dose: int=Field(..., gt=0)
    typeOfMedicine: str
    time: str
    routine: str
    status: str
    image: str
    isEnable: bool=True
    startingDate: str
    remainingDose: int=Field(..., ge=0)