from pydantic import BaseModel
from uuid import UUID

class Card(BaseModel):
    Id: UUID
    CardNumber: str
    CardType: str
    CardHolder: str
    ExpirationDate: str
    CVVCode: str