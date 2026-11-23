# Veritas JavaScript engine. Node built-ins plus vendored acorn (vendor/README.md); no packages are installed.
# Same pinned base as the vuln-notes lab, so building it downloads nothing new.
FROM node:26-alpine@sha256:6bd9ab43c0ec0190ca7b2d193906cb8b7edf6e7f4afa43ddeccd6452710bffb5
LABEL org.opencontainers.image.title="veritas-js-engine" \
      org.opencontainers.image.description="Parses JavaScript subjects into Veritas Program Model facts, without network"
WORKDIR /engine
COPY plugin.mjs engine.mjs ./
COPY vendor/acorn.mjs vendor/acorn.LICENSE ./vendor/
ENV NODE_NO_WARNINGS=1
USER 10001:10001
ENTRYPOINT ["node", "/engine/plugin.mjs"]
