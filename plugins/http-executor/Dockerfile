# Veritas HTTP executor plugin. Stdlib only; runs kernel-written request scripts through the gateway.
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
LABEL org.opencontainers.image.title="veritas-http-executor" \
      org.opencontainers.image.description="Runs Veritas request scripts through the egress gateway"
COPY plugin.py /plugin/plugin.py
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 10001:10001
ENTRYPOINT ["python", "-I", "/plugin/plugin.py"]
