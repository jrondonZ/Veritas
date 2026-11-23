# Veritas binary engine plugin. Stdlib only; reads PE, ELF, Mach-O, and .NET metadata without running anything.
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
LABEL org.opencontainers.image.title="veritas-binary-engine" \
      org.opencontainers.image.description="Reads executables' headers, imports, strings, hardening, and .NET metadata"
COPY plugin.py binfmt.py dotnet.py /plugin/
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 10001:10001
ENTRYPOINT ["python", "-I", "/plugin/plugin.py"]
