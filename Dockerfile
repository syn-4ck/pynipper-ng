# ── Stage 1: build ───────────────────────────────────────────────────────────
FROM python:3.13-slim-bookworm AS builder

WORKDIR /build

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN pip install --no-cache-dir --upgrade pip setuptools wheel

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

COPY . .
# Build the wheel directly (avoids pip build-isolation hitting pip._internal)
RUN python setup.py bdist_wheel --quiet \
    && pip install --no-cache-dir --prefix=/install --no-deps dist/*.whl

# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM python:3.13-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Update system packages to patch known CVEs in the base image
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /install /usr/local

RUN useradd -u 8877 --no-create-home --shell /sbin/nologin pynipper-ng
USER pynipper-ng

ENTRYPOINT ["pynipper-ng"]
