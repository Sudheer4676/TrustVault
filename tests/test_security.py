
import pytest
import app.main as main
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path, monkeypatch):
    # Give every test its own database and storage directory.
    test_db = tmp_path / "test_trustvault.db"
    test_storage = tmp_path / "test_storage"

    monkeypatch.setattr(main, "DB_PATH", str(test_db))
    monkeypatch.setattr(main, "STORAGE", test_storage)

    test_storage.mkdir(parents=True, exist_ok=True)
    main.init_db()

    with TestClient(main.app) as test_client:
        yield test_client


def register_user(client, email, role="owner"):
    response = client.post(
        "/auth/register",
        json={
            "email": email,
            "password": "TestPassword@123",
            "role": role,
        },
    )
    assert response.status_code == 200
    return response.json()


def login_user(client, email):
    response = client.post(
        "/auth/login",
        json={
            "email": email,
            "password": "TestPassword@123",
        },
    )
    assert response.status_code == 200
    return response.json()["access_token"]


def auth(token):
    return {"Authorization": f"Bearer {token}"}


def create_admin():
    admin_id = "test-admin-id"

    with main.db() as con:
        con.execute(
            """
            INSERT INTO users(id, email, password_hash, role)
            VALUES (?, ?, ?, ?)
            """,
            (
                admin_id,
                "admin@test.local",
                main.ph.hash("TestPassword@123"),
                "admin",
            ),
        )

    return admin_id


def test_health_endpoint(client):
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["status"] == "running"


def test_registration_and_login(client):
    register_user(client, "owner@test.local")
    token = login_user(client, "owner@test.local")

    assert isinstance(token, str)
    assert len(token) > 10


def test_duplicate_registration_is_rejected(client):
    register_user(client, "duplicate@test.local")

    response = client.post(
        "/auth/register",
        json={
            "email": "duplicate@test.local",
            "password": "TestPassword@123",
            "role": "owner",
        },
    )

    assert response.status_code == 409


def test_weak_password_is_rejected(client):
    response = client.post(
        "/auth/register",
        json={
            "email": "weak@test.local",
            "password": "short",
            "role": "owner",
        },
    )

    assert response.status_code == 400


def test_invalid_role_is_rejected(client):
    response = client.post(
        "/auth/register",
        json={
            "email": "admin2@test.local",
            "password": "TestPassword@123",
            "role": "admin",
        },
    )

    assert response.status_code == 400


def test_missing_token_is_rejected(client):
    response = client.get("/documents")
    assert response.status_code == 401


def test_invalid_token_is_rejected(client):
    response = client.get(
        "/documents",
        headers=auth("invalid-token"),
    )

    assert response.status_code == 401


def test_viewer_cannot_upload(client):
    register_user(client, "viewer@test.local", "viewer")
    token = login_user(client, "viewer@test.local")

    response = client.post(
        "/documents",
        headers=auth(token),
        files={"file": ("test.txt", b"hello", "text/plain")},
    )

    assert response.status_code == 403


def test_viewer_cannot_read_unshared_document(client):
    register_user(client, "owner@test.local")
    register_user(client, "viewer@test.local", "viewer")

    owner_token = login_user(client, "owner@test.local")
    viewer_token = login_user(client, "viewer@test.local")

    upload = client.post(
        "/documents",
        headers=auth(owner_token),
        files={"file": ("private.txt", b"private data", "text/plain")},
    )
    assert upload.status_code == 200

    document_id = upload.json()["id"]

    download = client.get(
        f"/documents/{document_id}/download",
        headers=auth(viewer_token),
    )

    assert download.status_code == 403


def test_grant_and_revoke_access(client):
    owner = register_user(client, "owner@test.local")
    viewer = register_user(client, "viewer@test.local", "viewer")

    owner_token = login_user(client, "owner@test.local")
    viewer_token = login_user(client, "viewer@test.local")

    upload = client.post(
        "/documents",
        headers=auth(owner_token),
        files={"file": ("shared.txt", b"shared data", "text/plain")},
    )
    assert upload.status_code == 200

    document_id = upload.json()["id"]

    grant = client.post(
        f"/documents/{document_id}/grants",
        headers=auth(owner_token),
        params={
            "target_user_id": viewer["id"],
            "permission": "read",
        },
    )
    assert grant.status_code == 200

    allowed = client.get(
        f"/documents/{document_id}/download",
        headers=auth(viewer_token),
    )
    assert allowed.status_code == 200

    revoke = client.delete(
        f"/documents/{document_id}/grants/{viewer['id']}",
        headers=auth(owner_token),
    )
    assert revoke.status_code == 200

    denied = client.get(
        f"/documents/{document_id}/download",
        headers=auth(viewer_token),
    )
    assert denied.status_code == 403


def test_viewer_cannot_grant_access(client):
    register_user(client, "owner@test.local")
    register_user(client, "viewer@test.local", "viewer")
    register_user(client, "other@test.local", "viewer")

    owner_token = login_user(client, "owner@test.local")
    viewer_token = login_user(client, "viewer@test.local")
    other = client.post(
        "/auth/login",
        json={
            "email": "other@test.local",
            "password": "TestPassword@123",
        },
    ).json()

    upload = client.post(
        "/documents",
        headers=auth(owner_token),
        files={"file": ("file.txt", b"data", "text/plain")},
    )
    document_id = upload.json()["id"]

    response = client.post(
        f"/documents/{document_id}/grants",
        headers=auth(viewer_token),
        params={
            "target_user_id": other.get("id", ""),
            "permission": "read",
        },
    )

    assert response.status_code == 403


def test_invalid_upload_is_rejected(client):
    register_user(client, "owner@test.local")
    token = login_user(client, "owner@test.local")

    response = client.post(
        "/documents",
        headers=auth(token),
        files={"file": ("malware.exe", b"not a valid file", "application/octet-stream")},
    )

    assert response.status_code == 415


def test_admin_only_audit_access(client):
    register_user(client, "owner@test.local")
    owner_token = login_user(client, "owner@test.local")

    response = client.get(
        "/admin/audit",
        headers=auth(owner_token),
    )

    assert response.status_code == 403


def test_admin_audit_integrity(client):
    create_admin()
    admin_token = login_user(client, "admin@test.local")

    response = client.get(
        "/admin/audit/verify",
        headers=auth(admin_token),
    )

    assert response.status_code == 200
    assert response.json()["valid"] is True
