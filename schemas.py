"""
Database Schemas for Hostel Gate Pass Management System (MongoDB)

Each Pydantic model corresponds to a MongoDB collection.
Collection name is the lowercase of the class name.
"""
from pydantic import BaseModel, Field, EmailStr
from typing import Optional, Literal
from datetime import datetime

class Student(BaseModel):
    full_name: str = Field(..., description="Student full name")
    email: EmailStr = Field(..., description="Student email (login)")
    password_hash: str = Field(..., description="Hashed password")
    phone: Optional[str] = Field(None, description="Student phone number")
    roll_no: Optional[str] = Field(None, description="Roll number")
    hostel: Optional[str] = Field(None, description="Hostel/Block name")
    room_no: Optional[str] = Field(None, description="Room number")
    parent_id: Optional[str] = Field(None, description="Reference to parent document _id as string")
    role: Literal['student'] = 'student'
    is_active: bool = True

class Parent(BaseModel):
    full_name: str
    email: EmailStr
    phone: Optional[str] = None
    student_id: Optional[str] = None
    role: Literal['parent'] = 'parent'
    is_active: bool = True

class Warden(BaseModel):
    full_name: str
    email: EmailStr
    password_hash: str
    hostel: Optional[str] = None
    role: Literal['warden'] = 'warden'
    is_active: bool = True

class Admin(BaseModel):
    full_name: str
    email: EmailStr
    password_hash: str
    role: Literal['admin'] = 'admin'
    is_active: bool = True

class OTPRecord(BaseModel):
    request_id: str
    parent_id: str
    otp_hash: str
    salt: str
    expires_at: datetime
    attempts: int = 0
    max_attempts: int = 5
    consumed: bool = False

class GatePassRequest(BaseModel):
    student_id: str
    reason: str
    from_datetime: datetime
    to_datetime: datetime
    destination: Optional[str] = None
    status: Literal['submitted', 'parent_verified', 'approved', 'rejected'] = 'submitted'
    parent_verified_at: Optional[datetime] = None
    warden_id: Optional[str] = None
    warden_action_at: Optional[datetime] = None

class QRCode(BaseModel):
    request_id: str
    payload: dict
    image_b64: Optional[str] = None
    generated_at: datetime

class SecurityLog(BaseModel):
    request_id: str
    student_id: str
    action: Literal['scan_entry', 'scan_exit', 'scan_status']
    status_at_scan: str
    meta: Optional[dict] = None

class Session(BaseModel):
    user_id: str
    role: Literal['student', 'warden', 'admin']
    token: str
    expires_at: datetime
