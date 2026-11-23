# Veritas egress gateway, built locally from this repo with `veritas images build` (no registry needed).
# Build context: the repository root, narrowed by Dockerfile.dockerignore to exactly what is copied below.
# The image holds only veritas.core and veritas.gateway; tests/unit/test_architecture.py keeps that true.
FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928
LABEL org.opencontainers.image.title="veritas-gateway" \
      org.opencontainers.image.description="Scope-enforcing egress gateway for Veritas sandboxes"
COPY docker/gateway/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --no-deps --require-hashes -r /tmp/requirements.txt && rm /tmp/requirements.txt
COPY src/veritas/__init__.py /opt/veritas/veritas/__init__.py
COPY src/veritas/core /opt/veritas/veritas/core
COPY src/veritas/gateway /opt/veritas/veritas/gateway
ENV PYTHONPATH=/opt/veritas PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["python", "-m", "veritas.gateway"]
