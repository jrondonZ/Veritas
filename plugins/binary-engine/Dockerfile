# Veritas binary engine plugin. Stdlib only; reads PE, ELF, Mach-O, and .NET metadata without running anything.
FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928
LABEL org.opencontainers.image.title="veritas-binary-engine" \
      org.opencontainers.image.description="Reads executables' headers, imports, strings, hardening, and .NET metadata"
COPY plugin.py binfmt.py dotnet.py /plugin/
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 10001:10001
ENTRYPOINT ["python", "-I", "/plugin/plugin.py"]
