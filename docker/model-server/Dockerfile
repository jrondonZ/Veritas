# Veritas model server: llama.cpp's llama-server, pinned by digest, plus a stdio relay. It runs with no network at all.
# Base: ghcr.io/ggml-org/llama.cpp:server (CPU build), digest recorded 2026-11-19.
FROM ghcr.io/ggml-org/llama.cpp:server@sha256:5b43086e3ba7ea5794d72904654f6cd41224a9b1c6ac0398f4940ee380d30f23
LABEL org.opencontainers.image.title="veritas-model-server" \
      org.opencontainers.image.description="llama-server for Veritas: loopback only, inside a container with no network"
COPY relay.sh install.sh /veritas/
# A new named volume copies ownership from its mount point, so the weights volume becomes writable by the install step.
RUN chmod 0555 /veritas/relay.sh /veritas/install.sh && mkdir -p /models && chown 10001:10001 /models
USER 10001:10001
ENTRYPOINT ["/app/llama-server"]
