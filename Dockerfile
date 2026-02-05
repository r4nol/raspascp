# syntax=docker/dockerfile:1

FROM python:3.12-slim AS builder
WORKDIR /build

COPY . /build

RUN python -m venv /opt/venv \
    && if [ -f /build/app/requirements.txt ]; then \
         /opt/venv/bin/pip install --no-cache-dir -r /build/app/requirements.txt; \
       else \
         echo "[builder] No app/requirements.txt found. Skipping dependency install."; \
       fi

FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_PORT=8080

WORKDIR /app

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system app \
    && useradd --system --gid app --create-home --home-dir /home/app app

COPY --from=builder /opt/venv /opt/venv
COPY --from=builder /build /app

COPY scripts/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh \
    && chown -R app:app /app /opt/venv

ENV PATH="/opt/venv/bin:$PATH"

USER app
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
