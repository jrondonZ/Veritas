# Veritas conformance harness for JavaScript implementations. Node built-ins only; same pinned base as the lab.
FROM node:24-alpine@sha256:116b800c3754b440ee0aa3ed2f20f5bf3d99a554bfd9adeea09ea8017f6e85f5
LABEL org.opencontainers.image.title="veritas-conformance-js" \
      org.opencontainers.image.description="Runs a clean-room implementation against conformance vectors, without network"
COPY harness.mjs /harness/harness.mjs
ENV NODE_NO_WARNINGS=1
USER 10001:10001
ENTRYPOINT ["node", "/harness/harness.mjs"]
