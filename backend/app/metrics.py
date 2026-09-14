from __future__ import annotations

from collections import defaultdict
from threading import Lock


class Metrics:
    def __init__(self) -> None:
        self._lock = Lock()
        self.requests = 0
        self.errors = 0
        self.request_count: dict[tuple[str, str, int], int] = defaultdict(int)
        self.latency_seconds: dict[tuple[str, str], list[float]] = defaultdict(list)
        self.assessment_stages: dict[str, int] = defaultdict(int)

    def observe_request(self, method: str, path: str, status: int, elapsed: float) -> None:
        with self._lock:
            self.requests += 1
            if status >= 400:
                self.errors += 1
            self.request_count[(method, path, status)] += 1
            self.latency_seconds[(method, path)].append(elapsed)

    def assessment_stage(self, stage: str) -> None:
        with self._lock:
            self.assessment_stages[stage] += 1

    def render(self) -> str:
        with self._lock:
            lines = [
                "# HELP soc_inspect_requests_total HTTP requests.",
                "# TYPE soc_inspect_requests_total counter",
                f"soc_inspect_requests_total {self.requests}",
                "# HELP soc_inspect_errors_total HTTP 5xx responses.",
                "# TYPE soc_inspect_errors_total counter",
                f"soc_inspect_errors_total {self.errors}",
                "# HELP soc_inspect_request_duration_seconds HTTP request latency.",
                "# TYPE soc_inspect_request_duration_seconds summary",
            ]
            for (method, path), values in self.latency_seconds.items():
                labels = f'method="{method}",path="{path}"'
                lines.append(f'soc_inspect_request_duration_seconds_count{{{labels}}} {len(values)}')
                lines.append(f'soc_inspect_request_duration_seconds_sum{{{labels}}} {sum(values):.6f}')
            lines += [
                "# HELP soc_inspect_assessment_stages_total Assessment pipeline stages.",
                "# TYPE soc_inspect_assessment_stages_total counter",
            ]
            for stage, count in self.assessment_stages.items():
                lines.append(f'soc_inspect_assessment_stages_total{{stage="{stage}"}} {count}')
            return "\n".join(lines) + "\n"


metrics = Metrics()
