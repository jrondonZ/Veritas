# Veritas query-log sensor plugin. Stdlib only; reads an owned app's SQL statement log from a read-only mount.
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
LABEL org.opencontainers.image.title="veritas-query-log-sensor" \
      org.opencontainers.image.description="Reads a Veritas lab's SQL statement log without network access"
COPY plugin.py /plugin/plugin.py
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 10001:10001
ENTRYPOINT ["python", "-I", "/plugin/plugin.py"]
