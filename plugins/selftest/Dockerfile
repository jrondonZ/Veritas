# Veritas self-test plugin and escape-suite echo target. Stdlib only.
FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928
LABEL org.opencontainers.image.title="veritas-selftest" \
      org.opencontainers.image.description="Veritas sandbox escape-suite plugin and echo target"
COPY plugin.py /plugin/plugin.py
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 10001:10001
ENTRYPOINT ["python", "-I", "/plugin/plugin.py"]
