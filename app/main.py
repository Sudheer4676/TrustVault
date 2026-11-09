import os
import sqlite3
import hashlib
import hmac
import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import FileResponse, HTMLResponse
from fastapi import Request
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from pydantic import BaseModel
APP_SECRET = os.getenv("APP_SECRET")
if not APP_SECRET or len(APP_SECRET) < 32:
    raise RuntimeError("APP_SECRET must be set to a random secret of at least 32 characters")

DB_PATH = os.getenv("DATABASE_PATH", "trustvault.db")
STORAGE = Path(os.getenv("STORAGE_PATH", "storage"))
STORAGE.mkdir(parents=True, exist_ok=True)
ph = PasswordHasher()

TOKEN_TTL_SECONDS = 3600
MAX_UPLOAD_BYTES = 5 * 1024 * 1024

serializer = URLSafeTimedSerializer(
    APP_SECRET,
    salt="trustvault-auth"
)


app = FastAPI(title="TrustVault API", version="0.1.0")

def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    with db() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS users(
            id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL, role TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS documents(
            id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, name TEXT NOT NULL,
            category TEXT NOT NULL, stored_name TEXT NOT NULL,
            content_type TEXT, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS grants(
            document_id TEXT NOT NULL, user_id TEXT NOT NULL,
            permission TEXT NOT NULL, PRIMARY KEY(document_id,user_id)
        );
        CREATE TABLE IF NOT EXISTS audit(
            id INTEGER PRIMARY KEY AUTOINCREMENT, actor_id TEXT NOT NULL,
            action TEXT NOT NULL, document_id TEXT, created_at TEXT NOT NULL,
            previous_hash TEXT NOT NULL, event_hash TEXT NOT NULL
        );
        """)
init_db()


def audit(actor, action, document_id=None):
    with db() as con:
        row = con.execute("SELECT event_hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
        previous = row["event_hash"] if row else "GENESIS"
        created = datetime.now(timezone.utc).isoformat()
        payload = json.dumps([actor, action, document_id, created, previous], separators=(",", ":"))
        digest = hashlib.sha256(payload.encode()).hexdigest()
        con.execute(
            "INSERT INTO audit(actor_id,action,document_id,created_at,previous_hash,event_hash) VALUES(?,?,?,?,?,?)",
            (actor, action, document_id, created, previous, digest)
        )


bearer_scheme = HTTPBearer(auto_error=False)


def current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    if credentials is None:
        raise HTTPException(401, "Missing bearer token")

    token = credentials.credentials

    try:
        data = serializer.loads(token, max_age=TOKEN_TTL_SECONDS)
    except (BadSignature, SignatureExpired):
        raise HTTPException(401, "Invalid or expired token")

    with db() as con:
        user = con.execute(
            "SELECT id,email,role FROM users WHERE id=?",
            (data.get("sub"),)
        ).fetchone()

    if not user:
        raise HTTPException(401, "Unknown user")

    return dict(user)


def require_role(*roles):
    def check(user=Depends(current_user)):
        if user["role"] not in roles:
            raise HTTPException(403, "Insufficient role")
        return user
    return check


def can_read(con, doc, user):
    if user["role"] == "admin" or doc["owner_id"] == user["id"]:
        return True
    grant = con.execute(
        "SELECT permission FROM grants WHERE document_id=? AND user_id=?",
        (doc["id"], user["id"])
    ).fetchone()
    return bool(grant and grant["permission"] in ("read", "edit"))


def can_edit(con, doc, user):
    if user["role"] == "admin" or doc["owner_id"] == user["id"]:
        return True
    grant = con.execute(
        "SELECT permission FROM grants WHERE document_id=? AND user_id=?",
        (doc["id"], user["id"])
    ).fetchone()
    return bool(grant and grant["permission"] == "edit")


@app.get("/")
def health():
    return {"service": "TrustVault API", "status": "running", "warning": "development scaffold"}

class AuthRequest(BaseModel):
    email: str
    password: str
    role: str = "owner"
@app.post("/auth/register")
def register(payload: AuthRequest):
    email = payload.email.strip().lower()
    password = payload.password
    role = payload.role

    if role not in ("owner", "viewer"):
        raise HTTPException(400, "Only owner or viewer self-registration is allowed")

    if len(password) < 12:
        raise HTTPException(400, "Password must be at least 12 characters")

    user_id = str(uuid.uuid4())

    try:
        with db() as con:
            con.execute(
                "INSERT INTO users(id,email,password_hash,role) VALUES(?,?,?,?)",
                (user_id, email, ph.hash(password), role)
            )
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Email already registered")

    return {"id": user_id, "email": email, "role": role}

@app.post("/auth/login")
def login(payload: AuthRequest):
    email = payload.email.strip().lower()
    password = payload.password

    with db() as con:
        user = con.execute(
            "SELECT * FROM users WHERE email=?",
            (email,)
        ).fetchone()

    if not user:
        raise HTTPException(401, "Invalid credentials")

    try:
        password_valid = ph.verify(user["password_hash"], password)
    except VerificationError:
        password_valid = False

    if not password_valid:
        raise HTTPException(401, "Invalid credentials")

    token = serializer.dumps({"sub": user["id"]})
    audit(user["id"], "login")

    return {
        "access_token": token,
        "token_type": "bearer",
        "role": user["role"]
    }

@app.post("/documents")
async def upload_document(file: UploadFile = File(...), category: str = "general",
                          user=Depends(require_role("owner", "admin"))):
    content = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "File too large (5 MB maximum)")
    name = Path(file.filename or "").name
    if not name or name.startswith("."):
        raise HTTPException(400, "Invalid filename")
    # Minimal signature checks; extend with robust MIME/content validation.
    allowed = {
        ".pdf": content.startswith(b"%PDF-"),
        ".txt": True,
        ".png": content.startswith(b"\x89PNG\r\n\x1a\n"),
        ".jpg": content.startswith(b"\xff\xd8\xff"),
        ".jpeg": content.startswith(b"\xff\xd8\xff"),
    }
    ext = Path(name).suffix.lower()
    if ext not in allowed or not allowed[ext]:
        raise HTTPException(415, "Unsupported file type or invalid file signature")
    doc_id = str(uuid.uuid4())
    stored = doc_id + ext
    (STORAGE / stored).write_bytes(content)
    with db() as con:
        con.execute("""INSERT INTO documents
        (id,owner_id,name,category,stored_name,content_type,created_at)
        VALUES(?,?,?,?,?,?,?)""",
        (doc_id, user["id"], name, category, stored, file.content_type,
         datetime.now(timezone.utc).isoformat()))
    audit(user["id"], "upload", doc_id)
    return {"id": doc_id, "name": name, "category": category}


@app.get("/documents")
def list_documents(user=Depends(current_user), q: str = ""):
    with db() as con:
        rows = con.execute("SELECT * FROM documents WHERE name LIKE ? ORDER BY created_at DESC",
                           (f"%{q}%",)).fetchall()
        result = []
        for doc in rows:
            if can_read(con, doc, user):
                result.append({"id": doc["id"], "name": doc["name"],
                               "category": doc["category"], "owner_id": doc["owner_id"],
                               "created_at": doc["created_at"]})
    return result


@app.get("/documents/{document_id}/download")
def download_document(document_id: str, user=Depends(current_user)):
    with db() as con:
        doc = con.execute("SELECT * FROM documents WHERE id=?", (document_id,)).fetchone()
        if not doc:
            raise HTTPException(404, "Document not found")
        if not can_read(con, doc, user):
            audit(user["id"], "denied_download", document_id)
            raise HTTPException(403, "Access denied")
    path = STORAGE / doc["stored_name"]
    if not path.is_file():
        raise HTTPException(404, "Stored file missing")
    audit(user["id"], "download", document_id)
    return FileResponse(path, filename=doc["name"], media_type=doc["content_type"] or "application/octet-stream")


@app.post("/documents/{document_id}/grants")
def grant_access(document_id: str, target_user_id: str, permission: str,
                 user=Depends(current_user)):
    if permission not in ("read", "edit"):
        raise HTTPException(400, "Permission must be read or edit")
    with db() as con:
        doc = con.execute("SELECT * FROM documents WHERE id=?", (document_id,)).fetchone()
        if not doc:
            raise HTTPException(404, "Document not found")
        if doc["owner_id"] != user["id"] and user["role"] != "admin":
            raise HTTPException(403, "Only owner or admin can grant access")
        target = con.execute("SELECT id FROM users WHERE id=?", (target_user_id,)).fetchone()
        if not target:
            raise HTTPException(404, "User not found")
        con.execute("INSERT OR REPLACE INTO grants VALUES(?,?,?)",
                    (document_id, target_user_id, permission))
    audit(user["id"], "grant_" + permission, document_id)
    return {"document_id": document_id, "user_id": target_user_id, "permission": permission}


@app.delete("/documents/{document_id}/grants/{target_user_id}")
def revoke_access(document_id: str, target_user_id: str, user=Depends(current_user)):
    with db() as con:
        doc = con.execute("SELECT * FROM documents WHERE id=?", (document_id,)).fetchone()
        if not doc:
            raise HTTPException(404, "Document not found")
        if doc["owner_id"] != user["id"] and user["role"] != "admin":
            raise HTTPException(403, "Only owner or admin can revoke access")
        con.execute("DELETE FROM grants WHERE document_id=? AND user_id=?",
                    (document_id, target_user_id))
    audit(user["id"], "revoke_access", document_id)
    return {"revoked": True}


@app.get("/admin/audit")
def get_audit(user=Depends(require_role("admin"))):
    with db() as con:
        rows = con.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 500").fetchall()
    return [dict(row) for row in rows]


@app.get("/admin/audit/verify")
def verify_audit(user=Depends(require_role("admin"))):
    with db() as con:
        rows = con.execute("SELECT * FROM audit ORDER BY id ASC").fetchall()
    previous = "GENESIS"
    for row in rows:
        payload = json.dumps([row["actor_id"], row["action"], row["document_id"],
                              row["created_at"], previous], separators=(",", ":"))
        expected = hashlib.sha256(payload.encode()).hexdigest()
        if row["previous_hash"] != previous or not hmac.compare_digest(expected, row["event_hash"]):
            return {"valid": False, "broken_event_id": row["id"]}
        previous = row["event_hash"]
    return {"valid": True, "events_checked": len(rows)}

@app.get("/admin/dashboard")
def admin_dashboard(user=Depends(require_role("admin"))):
    with db() as con:
        total_users = con.execute(
            "SELECT COUNT(*) FROM users"
        ).fetchone()[0]

        total_documents = con.execute(
            "SELECT COUNT(*) FROM documents"
        ).fetchone()[0]

        total_owners = con.execute(
            "SELECT COUNT(*) FROM users WHERE role='owner'"
        ).fetchone()[0]

        total_viewers = con.execute(
            "SELECT COUNT(*) FROM users WHERE role='viewer'"
        ).fetchone()[0]

        recent_documents = con.execute("""
            SELECT name, category, owner_id, created_at
            FROM documents
            ORDER BY created_at DESC
            LIMIT 5
        """).fetchall()

        recent_activity = con.execute("""
            SELECT actor_id, action, document_id, created_at
            FROM audit
            ORDER BY id DESC
            LIMIT 10
        """).fetchall()

    return {
        "total_users": total_users,
        "total_documents": total_documents,
        "total_owners": total_owners,
        "total_viewers": total_viewers,
        "recent_documents": [dict(row) for row in recent_documents],
        "recent_activity": [dict(row) for row in recent_activity]
    }

@app.get("/admin", response_class=HTMLResponse)
def admin_dashboard_page():
    return HTMLResponse("""
<!DOCTYPE html>
<html>
<head>
    <title>TrustVault Admin Dashboard</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {
            margin: 0;
            padding: 30px;
            background: #101827;
            color: white;
            font-family: Arial, sans-serif;
        }
        h1 { color: #60a5fa; }
        .card {
            background: #1e293b;
            padding: 22px;
            border-radius: 12px;
            margin: 12px 0;
        }
        .cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 15px;
        }
        .number {
            font-size: 32px;
            color: #60a5fa;
            font-weight: bold;
        }
        input, button {
            padding: 12px;
            border-radius: 6px;
            border: none;
            margin: 5px;
        }
        input { width: 300px; max-width: 90%; }
        button {
            background: #2563eb;
            color: white;
            cursor: pointer;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        td, th {
            padding: 10px;
            border-bottom: 1px solid #475569;
            text-align: left;
        }
        .table-wrap { overflow-x: auto; }
        #status { color: #fbbf24; }
    </style>
</head>
<body>

<h1>TrustVault Admin Dashboard</h1>
<p>Secure Document Management System</p>

<div class="card">
    <h3>Admin Authentication</h3>
    <input id="token" type="password"
           placeholder="Paste Admin access token">
    <button onclick="loadDashboard()">Load Dashboard</button>
    <p id="status">Enter your Admin token to continue.</p>
</div>

<div class="cards">
    <div class="card">
        <h3>Total Users</h3>
        <div class="number" id="users">--</div>
    </div>
    <div class="card">
        <h3>Total Documents</h3>
        <div class="number" id="documents">--</div>
    </div>
    <div class="card">
        <h3>Owners</h3>
        <div class="number" id="owners">--</div>
    </div>
    <div class="card">
        <h3>Viewers</h3>
        <div class="number" id="viewers">--</div>
    </div>
</div>

<div class="card">
    <h2>Recent Documents</h2>
    <div class="table-wrap">
        <table>
            <thead>
                <tr><th>Name</th><th>Category</th><th>Owner ID</th><th>Date</th></tr>
            </thead>
            <tbody id="document-list"></tbody>
        </table>
    </div>
</div>

<div class="card">
    <h2>Recent Audit Activity</h2>
    <div class="table-wrap">
        <table>
            <thead>
                <tr><th>Actor ID</th><th>Action</th><th>Document ID</th><th>Date</th></tr>
            </thead>
            <tbody id="activity-list"></tbody>
        </table>
    </div>
</div>

<script>
async function loadDashboard() {
    const token = document.getElementById("token").value.trim();
    const status = document.getElementById("status");

    if (!token) {
        status.textContent = "Please enter your Admin token.";
        return;
    }

    status.textContent = "Loading dashboard...";

    try {
        const response = await fetch("/admin/dashboard", {
            headers: { "Authorization": "Bearer " + token }
        });

        if (!response.ok) {
            status.textContent = "Access failed: HTTP " + response.status;
            return;
        }

        const data = await response.json();

        document.getElementById("users").textContent = data.total_users;
        document.getElementById("documents").textContent = data.total_documents;
        document.getElementById("owners").textContent = data.total_owners;
        document.getElementById("viewers").textContent = data.total_viewers;

        function addRows(id, items, fields) {
            const body = document.getElementById(id);
            body.replaceChildren();

            if (items.length === 0) {
                const row = document.createElement("tr");
                const cell = document.createElement("td");
                cell.textContent = "No records found";
                cell.colSpan = fields.length;
                row.appendChild(cell);
                body.appendChild(row);
                return;
            }

            items.forEach(item => {
                const row = document.createElement("tr");
                fields.forEach(field => {
                    const cell = document.createElement("td");
                    cell.textContent = item[field] ?? "-";
                    row.appendChild(cell);
                });
                body.appendChild(row);
            });
        }

        addRows("document-list", data.recent_documents,
            ["name", "category", "owner_id", "created_at"]);

        addRows("activity-list", data.recent_activity,
            ["actor_id", "action", "document_id", "created_at"]);

        status.textContent = "Dashboard loaded successfully.";
    } catch (error) {
        status.textContent = "Unable to connect to the server.";
    }
}
</script>

</body>
</html>
""")
def ensure_admin():
    email = os.getenv("ADMIN_EMAIL", "").strip().lower()
    password = os.getenv("ADMIN_PASSWORD", "")

    if not email and not password:
        return

    if not email or not password:
        raise RuntimeError("Both ADMIN_EMAIL and ADMIN_PASSWORD must be configured")

    if len(password) < 16:
        raise RuntimeError("ADMIN_PASSWORD must be at least 16 characters")

    with db() as con:
        existing = con.execute(
            "SELECT id, role FROM users WHERE email=?",
            (email,)
        ).fetchone()

        if existing:
            if existing["role"] != "admin":
                raise RuntimeError(
                    "ADMIN_EMAIL already belongs to a non-admin account"
                )
            return

        con.execute(
            "INSERT INTO users(id,email,password_hash,role) VALUES(?,?,?,?)",
            (str(uuid.uuid4()), email, ph.hash(password), "admin")
        )


ensure_admin()