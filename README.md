# TrustVault starter

A learning scaffold for a secure document-sharing application. This is **not production-ready** and is not a completed hackathon submission.

## Requirements
- Python 3.10+
- Install dependencies: `python -m pip install -r requirements.txt`
- Copy `.env.example` to `.env` and replace the development secret.
- Run: `uvicorn app.main:app --reload`
- API docs: `http://127.0.0.1:8000/docs`
- Tests: `pytest -q`

## Current scaffold
- Password hashing with Argon2
- Bearer-token authentication
- Admin / owner / viewer role checks
- Per-document grants
- Private local file storage
- Basic audit events and integrity-chain verification
- Basic security tests

## Important limitations
This scaffold is deliberately incomplete. Before any public deployment, review and improve token revocation, rate limiting, account provisioning, file scanning, durable private object storage, database migrations, audit-log durability, CSRF/CORS policy, secrets management, and production configuration. Do not claim unsupported features work. Do not deploy with demo credentials or the development secret.

## Demo account
No production/demo account is created automatically. Create accounts through a controlled provisioning process before using the system.
