# API notes (starter)

Run the app and inspect `/docs` for the current OpenAPI schema.

Endpoints currently scaffolded:
- `POST /auth/register`
- `POST /auth/login`
- `POST /documents`
- `GET /documents`
- `GET /documents/{document_id}/download`
- `POST /documents/{document_id}/grants`
- `DELETE /documents/{document_id}/grants/{user_id}`
- `GET /admin/audit`

This list is a starting point, not a guarantee that every challenge requirement is complete. Verify actual behavior before documenting it as working.
