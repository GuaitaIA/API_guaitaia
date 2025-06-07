# app/api/v1/api.py
from fastapi import APIRouter
from app.api.v1.endpoints import auth, users, detection, results

api_router = APIRouter()

api_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
api_router.include_router(users.router, prefix="/users", tags=["Users"])
api_router.include_router(detection.router, prefix="/detection", tags=["Wildfire Detection"])
api_router.include_router(results.router, prefix="/results", tags=["Results"])
