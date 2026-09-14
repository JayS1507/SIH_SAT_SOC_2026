from fastapi.testclient import TestClient
import jwt

try:
    from app.ingestion import IngestionError, parse_sql_export
    from app.main import app
except ModuleNotFoundError:
    from backend.app.ingestion import IngestionError, parse_sql_export
    from backend.app.main import app


def test_restricted_postgres_insert_and_copy():
    insert = b"INSERT INTO public.events (id, ok) VALUES (1, TRUE), (2, FALSE);\n"
    assert parse_sql_export(insert) == [
        {"id": 1, "ok": True, "_table": "public.events"},
        {"id": 2, "ok": False, "_table": "public.events"},
    ]
    copy = b"COPY events (id,name) FROM STDIN;\n1,Alice\n2,Bob\n\\.\n"
    assert parse_sql_export(copy)[1]["name"] == "Bob"


def test_sql_rejects_arbitrary_statements():
    try:
        parse_sql_export(b"DROP TABLE events;")
    except IngestionError as exc:
        assert "only INSERT and COPY" in str(exc)
    else:
        raise AssertionError("unsafe SQL was accepted")


def test_prometheus_metrics_endpoint(monkeypatch):
    monkeypatch.setenv("DEMO_AUTH_DISABLED", "true")
    response = TestClient(app).get("/metrics")
    assert response.status_code == 200
    assert "soc_inspect_requests_total" in response.text
    assert response.headers["content-type"].startswith("text/plain")


def test_keycloak_claim_roles_are_supported(monkeypatch):
    try:
        from app.auth import _claims
    except ModuleNotFoundError:
        from backend.app.auth import _claims
    from starlette.requests import Request

    monkeypatch.setenv("DEMO_AUTH_DISABLED", "false")
    monkeypatch.setenv("OIDC_ISSUER", "https://keycloak.example/realms/demo")
    monkeypatch.setenv("OIDC_AUDIENCE", "soc-inspect")

    class Key:
        key = "public-key"

    class Client:
        def __init__(self, _url):
            pass

        def get_signing_key_from_jwt(self, _token):
            return Key()

    monkeypatch.setattr(jwt, "PyJWKClient", Client)
    monkeypatch.setattr(jwt, "decode", lambda *args, **kwargs: {
        "sub": "alice", "iss": "https://keycloak.example/realms/demo",
        "aud": "soc-inspect", "realm_access": {"roles": ["reviewer"]},
    })
    request = Request({
        "type": "http", "method": "GET", "path": "/",
        "headers": [(b"authorization", b"Bearer token")],
        "query_string": b"", "server": ("test", 80), "scheme": "http",
    })
    assert _claims(request)["roles"] == ["reviewer"]
