import re
import secrets
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.auth import hash_password, verify_password, create_access_token, get_current_user
from app.models.models import User
from app.schemas.schemas import UserCreate, UserResponse, Token, LoginRequest

router = APIRouter()
GUEST_BROWSER_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{8,64}$")

@router.post("/register", response_model=UserResponse)
def register(user_data: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == user_data.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    if db.query(User).filter(User.username == user_data.username).first():
        raise HTTPException(status_code=400, detail="Username already taken")

    if not user_data.password or len(user_data.password) < 4:
        raise HTTPException(status_code=400, detail="Password is too short")

    new_user = User(
        email=user_data.email,
        username=user_data.username,
        hashed_password=hash_password(user_data.password)
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return new_user


@router.post("/login", response_model=Token)
def login(login_data: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == login_data.email).first()

    if not user or not verify_password(login_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password"
        )

    access_token = create_access_token(data={"sub": user.email})

    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/guest", response_model=Token)
def guest_access(payload: dict | None = None, db: Session = Depends(get_db)):
    requested_browser_id = ""
    if isinstance(payload, dict):
        requested_browser_id = str(payload.get("browser_id") or "").strip().lower()

    if not GUEST_BROWSER_ID_PATTERN.fullmatch(requested_browser_id):
        requested_browser_id = secrets.token_hex(12)

    guest_email = f"guest+{requested_browser_id}@trustive.ai"
    guest_username = f"guest_{requested_browser_id.replace('-', '_')[:64]}"

    guest_user = db.query(User).filter(User.email == guest_email).first()
    if guest_user is None:
        guest_user = User(
            email=guest_email,
            username=guest_username,
            hashed_password=hash_password(secrets.token_urlsafe(24)),
            is_active=True,
        )

        db.add(guest_user)
        db.commit()
        db.refresh(guest_user)

    access_token = create_access_token(data={"sub": guest_user.email})
    return {"access_token": access_token, "token_type": "bearer"}


@router.get("/profile", response_model=UserResponse)
def get_profile(current_user: User = Depends(get_current_user)):
    return current_user
