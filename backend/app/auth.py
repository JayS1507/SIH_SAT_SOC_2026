from __future__ import annotations

import os
from typing import Any, Callable

from fastapi import Depends, HTTPException, Request

ROLES = {"supervisor", "reviewer", "auditor", "admin", "data_provider"}


def auth_disabled() -> bool:
    return os.getenv("DEMO_AUTH_DISABLED", "true").lower() in {"1", "true", "yes", "on"}


def _claims(request: Request) -> dict[str, Any]:
    if auth_disabled():
        return {"sub": "demo", "roles": ["admin"]}
    header = request.headers.get("Authorization", "")
    if not header.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail={"error": "Bearer token required"})
    token = header.split(" ", 1)[1].strip()
    try:
        import jwt
        issuer = os.getenv("OIDC_ISSUER", "").rstrip("/")
        audience = os.getenv("OIDC_AUDIENCE", "")
        if issuer:
            jwks_url = os.getenv("OIDC_JWKS_URL", f"{issuer}/protocol/openid-connect/certs")
            signing_key = jwt.PyJWKClient(jwks_url).get_signing_key_from_jwt(token).key
            claims = jwt.decode(token, signing_key, algorithms=["RS256"],
                                issuer=issuer, audience=audience or None,
                                options={"verify_aud": bool(audience)})
        else:
            claims = jwt.decode(token, os.getenv("JWT_SECRET", ""), algorithms=["HS256"],
                                audience=os.getenv("JWT_AUDIENCE") or None,
                                options={"verify_aud": bool(os.getenv("JWT_AUDIENCE"))})
    except Exception as exc:
        raise HTTPException(status_code=401, detail={"error": "Invalid or expired JWT"}) from exc
    roles = claims.get("roles", claims.get("role", []))
    if not roles and isinstance(claims.get("realm_access"), dict):
        roles = claims["realm_access"].get("roles", [])
    if not roles and isinstance(claims.get("resource_access"), dict):
        for client in claims["resource_access"].values():
            if isinstance(client, dict):
                roles = list(roles) + list(client.get("roles", []))
    if isinstance(roles, str):
        roles = [roles]
    claims["roles"] = [role for role in roles if role in ROLES]
    if not claims["roles"]:
        raise HTTPException(status_code=403, detail={"error": "Token has no supported role"})
    return claims


def require_roles(*allowed: str) -> Callable:
    async def dependency(request: Request) -> dict[str, Any]:
        claims = _claims(request)
        if not set(claims["roles"]).intersection(allowed):
            raise HTTPException(status_code=403, detail={"error": "Insufficient role", "required": list(allowed)})
        return claims
    return Depends(dependency)
