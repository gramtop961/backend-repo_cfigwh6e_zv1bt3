import os
import base64
import io
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta, timezone
from typing import Optional, Literal
import hashlib
import secrets

from fastapi import FastAPI, HTTPException, Depends, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse
from pydantic import BaseModel, EmailStr

from database import db, create_document, get_documents

# Optional: Use qrcode for QR generation
try:
    import qrcode
except Exception:  # pragma: no cover
    qrcode = None

app = FastAPI(title="Hostel Gate Pass Management API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------
# Utility functions
# -----------------------------

def now_utc():
    return datetime.now(timezone.utc)


def bcrypt_hash(password: str) -> str:
    """Hash password with sha256 + salt if passlib unavailable."""
    salt = secrets.token_hex(16)
    digest = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"sha256${salt}${digest}"


def bcrypt_verify(password: str, hashed: str) -> bool:
    try:
        algo, salt, digest = hashed.split("$")
        if algo != "sha256":
            return False
        return hashlib.sha256((salt + password).encode()).hexdigest() == digest
    except Exception:
        return False


def otp_hash(otp: str, salt: str) -> str:
    return hashlib.sha256((salt + otp).encode()).hexdigest()


def send_email(to_email: str, subject: str, html_body: str) -> bool:
    smtp_host = os.getenv("SMTP_HOST")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER")
    smtp_pass = os.getenv("SMTP_PASS")
    from_email = os.getenv("FROM_EMAIL", smtp_user or "no-reply@example.com")

    if not smtp_host or not smtp_user or not smtp_pass:
        # In dev, log to console and treat as sent
        print("[DEV EMAIL] To:", to_email)
        print("Subject:", subject)
        print("Body:", html_body)
        return True

    msg = MIMEMultipart()
    msg["From"] = from_email
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(html_body, "html"))

    try:
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(from_email, to_email, msg.as_string())
        return True
    except Exception as e:
        print("Email send error:", e)
        return False


# -----------------------------
# Pydantic Models (requests)
# -----------------------------

class RegisterStudentRequest(BaseModel):
    full_name: str
    email: EmailStr
    password: str
    phone: Optional[str] = None
    roll_no: Optional[str] = None
    hostel: Optional[str] = None
    room_no: Optional[str] = None
    parent_name: str
    parent_email: EmailStr
    parent_phone: Optional[str] = None


class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    role: Literal["student", "warden", "admin"] = "student"


class ApplyPassRequest(BaseModel):
    token: str
    reason: str
    from_datetime: datetime
    to_datetime: datetime
    destination: Optional[str] = None


class SendOTPRequest(BaseModel):
    request_id: str


class VerifyOTPRequest(BaseModel):
    request_id: str
    otp: str


class WardenActionRequest(BaseModel):
    token: str
    request_id: str
    action: Literal["approve", "reject"]


class SecurityScanRequest(BaseModel):
    request_id: Optional[str] = None
    payload: Optional[dict] = None
    action: Literal["scan_entry", "scan_exit", "scan_status"] = "scan_status"


# -----------------------------
# Session Helpers
# -----------------------------

def create_session(user_id: str, role: str) -> str:
    token = secrets.token_urlsafe(32)
    session = {
        "user_id": user_id,
        "role": role,
        "token": token,
        "expires_at": now_utc() + timedelta(hours=12),
        "created_at": now_utc(),
        "updated_at": now_utc(),
    }
    db["session"].insert_one(session)
    return token


def require_session(token: str, role: Optional[str] = None) -> dict:
    s = db["session"].find_one({"token": token})
    if not s:
        raise HTTPException(status_code=401, detail="Invalid session token")
    if s.get("expires_at") and s["expires_at"] < now_utc():
        raise HTTPException(status_code=401, detail="Session expired")
    if role and s.get("role") != role:
        raise HTTPException(status_code=403, detail="Insufficient role")
    return s


# -----------------------------
# Routes
# -----------------------------

@app.get("/")
def root():
    return {"message": "Hostel Gate Pass Management API", "status": "ok"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set",
        "database_name": "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set",
        "connection_status": "Not Connected",
        "collections": [],
    }
    try:
        if db is not None:
            response["database"] = "✅ Connected"
            try:
                response["collections"] = db.list_collection_names()[:10]
                response["connection_status"] = "Connected"
            except Exception as e:
                response["database"] = f"⚠️ Connected but error: {str(e)[:80]}"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:80]}"
    return response


# 1) Register Student + Parent
@app.post("/api/registerStudent")
def register_student(req: RegisterStudentRequest):
    # Check existing
    if db["student"].find_one({"email": req.email.lower()}):
        raise HTTPException(status_code=409, detail="Student already exists")
    parent = db["parent"].find_one({"email": req.parent_email.lower()})
    if not parent:
        parent_doc = {
            "full_name": req.parent_name,
            "email": req.parent_email.lower(),
            "phone": req.parent_phone,
            "role": "parent",
            "is_active": True,
            "created_at": now_utc(),
            "updated_at": now_utc(),
        }
        parent_id = db["parent"].insert_one(parent_doc).inserted_id
    else:
        parent_id = parent["_id"]

    student_doc = {
        "full_name": req.full_name,
        "email": req.email.lower(),
        "password_hash": bcrypt_hash(req.password),
        "phone": req.phone,
        "roll_no": req.roll_no,
        "hostel": req.hostel,
        "room_no": req.room_no,
        "parent_id": str(parent_id),
        "role": "student",
        "is_active": True,
        "created_at": now_utc(),
        "updated_at": now_utc(),
    }
    student_id = db["student"].insert_one(student_doc).inserted_id
    token = create_session(str(student_id), "student")
    return {"message": "Registered", "student_id": str(student_id), "token": token}


# 2) Login
@app.post("/api/login")
def login(req: LoginRequest):
    collection = req.role
    if collection == "student":
        user = db["student"].find_one({"email": req.email.lower()})
    elif collection == "warden":
        user = db["warden"].find_one({"email": req.email.lower()})
    else:
        user = db["admin"].find_one({"email": req.email.lower()})

    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if not bcrypt_verify(req.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_session(str(user["_id"]), collection)
    return {"message": "Logged in", "role": collection, "token": token, "user_id": str(user["_id"])}


# 3) Apply Gate Pass (Student)
@app.post("/api/applyPass")
def apply_pass(req: ApplyPassRequest):
    s = require_session(req.token, role="student")
    student_id = s["user_id"]
    doc = {
        "student_id": student_id,
        "reason": req.reason,
        "from_datetime": req.from_datetime,
        "to_datetime": req.to_datetime,
        "destination": req.destination,
        "status": "submitted",
        "created_at": now_utc(),
        "updated_at": now_utc(),
    }
    request_id = db["gatepassrequest"].insert_one(doc).inserted_id
    return {"message": "Request submitted", "request_id": str(request_id)}


# 4) Send OTP to Parent
@app.post("/api/sendOTP")
def send_otp(req: SendOTPRequest):
    gp = db["gatepassrequest"].find_one({"_id": db.client.get_default_database().codec_options.document_class.objectid_class(req.request_id)}) if False else db["gatepassrequest"].find_one({"_id": None})
    # Fallback since converting string to ObjectId needs bson. Implement manually:
    from bson import ObjectId
    try:
        gp = db["gatepassrequest"].find_one({"_id": ObjectId(req.request_id)})
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid request id")
    if not gp:
        raise HTTPException(status_code=404, detail="Request not found")

    student = db["student"].find_one({"_id": ObjectId(gp["student_id"])}) if ObjectId.is_valid(gp["student_id"]) else None
    if not student:
        raise HTTPException(status_code=404, detail="Student not found")

    parent_id = student.get("parent_id")
    parent = db["parent"].find_one({"_id": ObjectId(parent_id)}) if parent_id and ObjectId.is_valid(parent_id) else None
    if not parent:
        raise HTTPException(status_code=404, detail="Parent not found")

    otp = f"{secrets.randbelow(1000000):06d}"
    salt = secrets.token_hex(8)
    record = {
        "request_id": req.request_id,
        "parent_id": str(parent["_id"]),
        "otp_hash": otp_hash(otp, salt),
        "salt": salt,
        "expires_at": now_utc() + timedelta(minutes=10),
        "attempts": 0,
        "max_attempts": 5,
        "consumed": False,
        "created_at": now_utc(),
        "updated_at": now_utc(),
    }
    db["otprecord"].insert_one(record)

    html = f"""
    <h2>OTP for Gate Pass Approval</h2>
    <p>Dear {parent.get('full_name','Parent')},</p>
    <p>Your OTP to approve the gate pass request is:</p>
    <h1 style='letter-spacing:6px'>{otp}</h1>
    <p>This OTP will expire in 10 minutes. Do not share it with anyone.</p>
    """
    sent = send_email(parent["email"], "Gate Pass Approval OTP", html)
    return {"message": "OTP sent" if sent else "OTP generated (email not configured)", "dev_otp": otp if not sent else None}


# 5) Verify OTP (Parent)
@app.post("/api/verifyOTP")
def verify_otp(req: VerifyOTPRequest):
    from bson import ObjectId
    gp = db["gatepassrequest"].find_one({"_id": ObjectId(req.request_id)}) if ObjectId.is_valid(req.request_id) else None
    if not gp:
        raise HTTPException(status_code=404, detail="Request not found")

    record = db["otprecord"].find_one({"request_id": req.request_id, "consumed": False}, sort=[("created_at", -1)])
    if not record:
        raise HTTPException(status_code=404, detail="OTP not found")

    if record.get("attempts", 0) >= record.get("max_attempts", 5):
        raise HTTPException(status_code=429, detail="Too many attempts")
    if record.get("expires_at") and record["expires_at"] < now_utc():
        raise HTTPException(status_code=400, detail="OTP expired")

    is_ok = otp_hash(req.otp, record["salt"]) == record["otp_hash"]
    db["otprecord"].update_one({"_id": record["_id"]}, {"$inc": {"attempts": 1}})
    if not is_ok:
        raise HTTPException(status_code=401, detail="Invalid OTP")

    db["otprecord"].update_one({"_id": record["_id"]}, {"$set": {"consumed": True, "updated_at": now_utc()}})
    db["gatepassrequest"].update_one({"_id": gp["_id"]}, {"$set": {"status": "parent_verified", "parent_verified_at": now_utc(), "updated_at": now_utc()}})
    return {"message": "Parent verified"}


# 6) Warden Approve/Reject
@app.post("/api/warden/approve")
def warden_action(req: WardenActionRequest):
    from bson import ObjectId
    s = require_session(req.token, role="warden")
    try:
        gp = db["gatepassrequest"].find_one({"_id": ObjectId(req.request_id)})
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid request id")
    if not gp:
        raise HTTPException(status_code=404, detail="Request not found")

    new_status = "approved" if req.action == "approve" else "rejected"
    db["gatepassrequest"].update_one({"_id": gp["_id"]}, {"$set": {
        "status": new_status,
        "warden_id": s["user_id"],
        "warden_action_at": now_utc(),
        "updated_at": now_utc(),
    }})

    # Generate QR on approve
    qr_b64 = None
    if new_status == "approved":
        payload = {
            "request_id": req.request_id,
            "student_id": gp["student_id"],
            "approved": True,
            "timestamp": now_utc().isoformat(),
        }
        if qrcode:
            img = qrcode.make(payload)
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            qr_b64 = base64.b64encode(buf.getvalue()).decode()
        doc = {
            "request_id": req.request_id,
            "payload": payload,
            "image_b64": qr_b64,
            "generated_at": now_utc(),
            "created_at": now_utc(),
            "updated_at": now_utc(),
        }
        db["qrcode"].insert_one(doc)

    return {"message": f"Request {new_status}", "qr_b64": qr_b64}


# 7) QR Generate (return image)
@app.get("/api/qr/generate/{request_id}")
def qr_generate(request_id: str):
    from bson import ObjectId
    gp = db["gatepassrequest"].find_one({"_id": ObjectId(request_id)}) if ObjectId.is_valid(request_id) else None
    if not gp:
        raise HTTPException(status_code=404, detail="Request not found")
    if gp.get("status") != "approved":
        raise HTTPException(status_code=400, detail="Request not approved")

    qr = db["qrcode"].find_one({"request_id": request_id}, sort=[("created_at", -1)])
    if qr and qr.get("image_b64"):
        img_bytes = base64.b64decode(qr["image_b64"])
        return StreamingResponse(io.BytesIO(img_bytes), media_type="image/png")

    # Generate on the fly
    payload = {
        "request_id": request_id,
        "student_id": gp["student_id"],
        "approved": True,
        "timestamp": now_utc().isoformat(),
    }
    if not qrcode:
        return JSONResponse({"payload": payload})
    img = qrcode.make(payload)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return StreamingResponse(buf, media_type="image/png")


# 8) Security Scan
@app.post("/api/security/scan")
def security_scan(req: SecurityScanRequest):
    # payload or request_id
    from bson import ObjectId
    rid = req.request_id or (req.payload or {}).get("request_id")
    if not rid:
        raise HTTPException(status_code=400, detail="request_id or payload.request_id required")
    gp = db["gatepassrequest"].find_one({"_id": ObjectId(rid)}) if ObjectId.is_valid(rid) else None
    if not gp:
        raise HTTPException(status_code=404, detail="Request not found")

    status_at_scan = gp.get("status")
    log = {
        "request_id": rid,
        "student_id": gp.get("student_id"),
        "action": req.action,
        "status_at_scan": status_at_scan,
        "meta": req.payload,
        "created_at": now_utc(),
        "updated_at": now_utc(),
    }
    db["securitylog"].insert_one(log)

    ok = status_at_scan == "approved"
    return {"valid": ok, "status": status_at_scan}


# 9) Logs
@app.get("/api/logs")
def get_logs(limit: int = 50):
    logs = list(db["securitylog"].find({}, sort=[("created_at", -1)]).limit(min(limit, 200)))
    # Convert ObjectIds to strings
    def _clean(d):
        d = dict(d)
        d["_id"] = str(d["_id"]) if "_id" in d else None
        return d
    return {"logs": [_clean(l) for l in logs]}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
