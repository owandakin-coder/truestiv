from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.auth import get_current_user
from app.models.models import User, TrustedContact
from typing import List

router = APIRouter()

@router.get("/contacts", response_model=List[dict])
def get_contacts(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    contacts = db.query(TrustedContact).filter(TrustedContact.user_id == current_user.id).all()
    return [{"id": c.id, "email": c.email, "name": c.name, "trust_level": c.trust_level, "created_at": str(c.created_at)} for c in contacts]

@router.post("/contacts", response_model=dict)
def add_contact(contact_data: dict, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    existing = db.query(TrustedContact).filter(
        TrustedContact.user_id == current_user.id,
        TrustedContact.email == contact_data["email"]
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="Contact already exists")

    contact = TrustedContact(
        user_id=current_user.id,
        email=contact_data["email"],
        name=contact_data.get("name", ""),
        trust_level=contact_data.get("trust_level", "medium")
    )
    db.add(contact)
    db.commit()
    db.refresh(contact)
    return {"id": contact.id, "email": contact.email, "name": contact.name, "trust_level": contact.trust_level}

@router.delete("/contacts/{contact_id}", response_model=dict)
def delete_contact(contact_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    contact = db.query(TrustedContact).filter(
        TrustedContact.id == contact_id,
        TrustedContact.user_id == current_user.id
    ).first()
    if not contact:
        raise HTTPException(status_code=404, detail="Contact not found")
    db.delete(contact)
    db.commit()
    return {"success": True, "message": "Contact deleted"}

@router.put("/contacts/{contact_id}", response_model=dict)
def update_contact(contact_id: int, contact_data: dict, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    contact = db.query(TrustedContact).filter(
        TrustedContact.id == contact_id,
        TrustedContact.user_id == current_user.id
    ).first()
    if not contact:
        raise HTTPException(status_code=404, detail="Contact not found")
    if "name" in contact_data:
        contact.name = contact_data["name"]
    if "trust_level" in contact_data:
        contact.trust_level = contact_data["trust_level"]
    db.commit()
    return {"id": contact.id, "email": contact.email, "name": contact.name, "trust_level": contact.trust_level}