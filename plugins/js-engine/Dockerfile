# Veritas JavaScript engine. Node built-ins plus vendored acorn (vendor/README.md); no packages are installed.
# Same pinned base as the vuln-notes lab, so building it downloads nothing new.
FROM node:24-alpine@sha256:116b800c3754b440ee0aa3ed2f20f5bf3d99a554bfd9adeea09ea8017f6e85f5
LABEL org.opencontainers.image.title="veritas-js-engine" \
      org.opencontainers.image.description="Parses JavaScript subjects into Veritas Program Model facts, without network"
WORKDIR /engine
COPY plugin.mjs engine.mjs ./
COPY vendor/acorn.mjs vendor/acorn.LICENSE ./vendor/
ENV NODE_NO_WARNINGS=1
USER 10001:10001
ENTRYPOINT ["node", "/engine/plugin.mjs"]
