FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATABASE_URL=sqlite:////data/soc_inspect.db \
    ARTIFACT_STORAGE=local \
    ARTIFACT_LOCAL_DIR=/data/artifacts

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

RUN useradd --system --uid 10001 satsa && mkdir -p /data && chown satsa /data
USER satsa
VOLUME ["/data"]

EXPOSE 8000
ENTRYPOINT ["docker-entrypoint.sh"]
