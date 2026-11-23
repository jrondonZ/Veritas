# Veritas query-log sensor plugin. Stdlib only; reads an owned app's SQL statement log from a read-only mount.
FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928
LABEL org.opencontainers.image.title="veritas-query-log-sensor" \
      org.opencontainers.image.description="Reads a Veritas lab's SQL statement log without network access"
COPY plugin.py /plugin/plugin.py
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 10001:10001
ENTRYPOINT ["python", "-I", "/plugin/plugin.py"]
