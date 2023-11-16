from sqlalchemy import Column, ForeignKey, String, Integer, Boolean
from pydantic import BaseModel
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)
    role = Column(String)
    zones_id = Column(Integer, ForeignKey('zones.id'))

class Zones(Base):
    __tablename__ = "zones"

    id = Column(Integer, primary_key=True, index=True)
    timezone = Column(String)
    start_time = Column(Integer)
    end_time = Column(Integer)

class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    email: str | None = None

#class UserInDB(User):
#    hashed_password: str