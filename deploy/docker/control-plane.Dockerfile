# syntax=docker/dockerfile:1.7

FROM python:3.12-slim-bookworm AS builder

COPY --from=ghcr.io/astral-sh/uv:0.11.30 /uv /uvx /bin/

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=0

WORKDIR /workspace

COPY pyproject.toml ./
COPY uv.lock ./
COPY apps/control-plane/pyproject.toml apps/control-plane/pyproject.toml
COPY apps/control-plane/src apps/control-plane/src

RUN uv sync --locked --no-dev --package woland-guard-control-plane --no-editable

FROM python:3.12-slim-bookworm AS runtime

ENV PATH="/workspace/.venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --gid 10001 woland-guard \
    && useradd --uid 10001 --gid woland-guard --no-create-home \
        --shell /usr/sbin/nologin woland-guard

WORKDIR /workspace

COPY --from=builder --chown=woland-guard:woland-guard /workspace/.venv /workspace/.venv

USER 10001:10001

EXPOSE 8000

CMD ["uvicorn", "woland_guard_control_plane.main:app", "--host", "0.0.0.0", "--port", "8000"]
