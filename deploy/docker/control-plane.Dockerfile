# syntax=docker/dockerfile:1.7

FROM python:3.12-slim-bookworm AS builder

COPY --from=ghcr.io/astral-sh/uv:0.11.30 /uv /uvx /bin/

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=0

WORKDIR /workspace

COPY pyproject.toml ./
COPY uv.lock ./
COPY apps/agent/pyproject.toml apps/agent/pyproject.toml
COPY apps/agent/src apps/agent/src
COPY apps/control-plane/pyproject.toml apps/control-plane/pyproject.toml
COPY apps/control-plane/src apps/control-plane/src
COPY packages/contracts/pyproject.toml packages/contracts/pyproject.toml
COPY packages/contracts/src packages/contracts/src

RUN uv sync --locked --no-dev --package woland-guard-control-plane --no-editable

FROM builder AS test

ENV PATH="/workspace/.venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY tests tests
COPY scripts scripts
COPY deploy deploy
COPY compose.yaml ./compose.yaml
COPY compose.demo.yaml ./compose.demo.yaml
COPY alembic.ini ./alembic.ini
COPY migrations migrations
COPY detection-rules detection-rules

RUN uv sync --locked --all-packages

CMD ["pytest"]

FROM python:3.12-slim-bookworm AS runtime

ENV PATH="/workspace/.venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --gid 10001 woland-guard \
    && useradd --uid 10001 --gid woland-guard --no-create-home \
        --shell /usr/sbin/nologin woland-guard

WORKDIR /workspace

COPY --from=builder --chown=woland-guard:woland-guard /workspace/.venv /workspace/.venv
COPY --chown=woland-guard:woland-guard alembic.ini ./alembic.ini
COPY --chown=woland-guard:woland-guard migrations ./migrations
COPY --chown=woland-guard:woland-guard detection-rules ./detection-rules

USER 10001:10001

EXPOSE 8000

CMD ["uvicorn", "woland_guard_control_plane.main:app", "--host", "0.0.0.0", "--port", "8000"]
