# Veritas conformance harness for JavaScript implementations. Node built-ins only; same pinned base as the lab.
FROM node:26-alpine@sha256:6bd9ab43c0ec0190ca7b2d193906cb8b7edf6e7f4afa43ddeccd6452710bffb5
LABEL org.opencontainers.image.title="veritas-conformance-js" \
      org.opencontainers.image.description="Runs a clean-room implementation against conformance vectors, without network"
COPY harness.mjs /harness/harness.mjs
ENV NODE_NO_WARNINGS=1
USER 10001:10001
ENTRYPOINT ["node", "/harness/harness.mjs"]
