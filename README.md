# Hostel Gate Pass Management System

Smart, secure and production-grade system for managing hostel gate passes with parent OTP approval, warden authorization, QR validation at the gate, and real-time security logs.

Live Preview: Start the dev servers and open the frontend URL.

## Features
- Student registration and login
- Apply for gate pass with timeframe and destination
- Parent OTP approval (hashed, expiring, attempt-limited)
- Warden approve/reject with QR generation
- Security scan and status validation
- Admin dashboard for recent logs
- 3D royal landing page (Three.js + GSAP)

## Tech Stack
- Frontend: React + Vite + Tailwind CSS, React Router, Three.js, GSAP
- Backend: FastAPI
- Database: MongoDB (pymongo)

## Getting Started

### 1) Environment Variables
Create `.env` in both backend and frontend roots.

Backend `.env` example:
```
# MongoDB
DATABASE_URL=mongodb+srv://user:pass@cluster.mongodb.net/
DATABASE_NAME=gatepass

# Email (optional; if omitted, emails are logged to console)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=you@example.com
SMTP_PASS=app-specific-password
FROM_EMAIL=you@example.com
```

Frontend `.env` example:
```
# Point frontend to backend
VITE_BACKEND_URL=http://localhost:8000
```

### 2) Install & Run
From the workspace root, use the provided "Run Project" which installs dependencies for both services and starts dev servers.
- Frontend: http://localhost:3000
- Backend: http://localhost:8000

### 3) Seed Accounts (optional)
Insert initial users in MongoDB for warden/admin if needed; otherwise register students via UI.

### 4) API Overview
- POST /api/registerStudent
- POST /api/login
- POST /api/applyPass
- POST /api/sendOTP
- POST /api/verifyOTP
- POST /api/warden/approve
- GET  /api/qr/generate/{id}
- POST /api/security/scan
- GET  /api/logs

## Testing
Add end-to-end tests (Cypress/Playwright) and backend pytest for flows:
- Student registers → applies → parent OTP → warden approve → security scan → logs visible.

## Production Notes
- Enforce HTTPS and secure cookies for sessions in production
- Use a transactional email provider (Resend, SES, SendGrid)
- Add input validation and rate limiting on sensitive endpoints
- Enable code splitting and lazy routes in frontend
- Add RBAC guards and better error handling
