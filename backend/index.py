"""Vercel entrypoint: expose the FastAPI app with the `app` package importable."""
from app.main import app

__all__ = ["app"]
