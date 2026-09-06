from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..core.auth import issue_token
from ..db import get_db
from ..schemas import LoginRequest, TokenResponse
from ..services.identity import authenticate

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])


@router.post("/login", response_model=TokenResponse)
def login(request: LoginRequest, db: Session = Depends(get_db)) -> TokenResponse:
    employee = authenticate(db, request.email, request.password)
    return TokenResponse(token=issue_token(employee))

