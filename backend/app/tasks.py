from __future__ import annotations

import os
from typing import Callable, Any


def submit_assessment(task: Callable[..., Any], *args: Any, **kwargs: Any) -> tuple[str, Any]:
    broker = os.getenv("CELERY_BROKER_URL") or os.getenv("REDIS_URL")
    if broker:
        try:
            from celery import Celery
            app = Celery("soc_inspect", broker=broker, backend=os.getenv("CELERY_RESULT_BACKEND", broker))
            result = app.send_task("soc_inspect.assess", args=args, kwargs=kwargs)
            return "queued", result.id
        except Exception:
            pass
    return "completed", task(*args, **kwargs)
