# syntax=docker/dockerfile:1.7

FROM python:3.12-slim-bookworm@sha256:4766d8b510c428e595d74b9cc5bbb2fae8e26316fffb4adc89908d79aacd58a2 AS builder

COPY --from=ghcr.io/astral-sh/uv:0.11.30@sha256:93b61e21202b1dab861092748e46bbd6e0e41dd84f59b9174efd2353186e1b47 /uv /uvx /bin/

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

FROM python:3.12-slim-bookworm@sha256:4766d8b510c428e595d74b9cc5bbb2fae8e26316fffb4adc89908d79aacd58a2 AS runtime

ENV PATH="/workspace/.venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --gid 10001 woland-guard \
    && useradd --uid 10001 --gid woland-guard --no-create-home \
        --shell /usr/sbin/nologin woland-guard

# The app's own dependencies live in the .venv copied in below (uv-managed,
# excludes pip by design); this strips the base image's *system* pip and its
# installer siblings, which the runtime never invokes (uv, not pip, built the
# venv) but which otherwise sit in the image as unused attack surface, e.g.
# CVE-2026-8643. ensurepip installs these outside dpkg's database, so removing
# the files directly doesn't leave dpkg in an inconsistent state.
RUN rm -rf /usr/local/lib/python3.12/site-packages/pip* \
           /usr/local/lib/python3.12/site-packages/setuptools* \
           /usr/local/lib/python3.12/site-packages/wheel* \
    && rm -f /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.12

WORKDIR /workspace

COPY --from=builder --chown=woland-guard:woland-guard /workspace/.venv /workspace/.venv
COPY --chown=woland-guard:woland-guard alembic.ini ./alembic.ini
COPY --chown=woland-guard:woland-guard migrations ./migrations
COPY --chown=woland-guard:woland-guard detection-rules ./detection-rules

USER 10001:10001

EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=5 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health/ready', timeout=3)"]

CMD ["uvicorn", "woland_guard_control_plane.main:app", "--host", "0.0.0.0", "--port", "8000"]
