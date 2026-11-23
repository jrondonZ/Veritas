# INTENTIONALLY VULNERABLE LAB APP. Node built-ins only (http, node:sqlite): no npm dependencies.
FROM node:26-alpine@sha256:6bd9ab43c0ec0190ca7b2d193906cb8b7edf6e7f4afa43ddeccd6452710bffb5
LABEL org.opencontainers.image.title="veritas-lab-vuln-notes" \
      org.opencontainers.image.description="INTENTIONALLY VULNERABLE Veritas lab app; never expose it"
WORKDIR /app
COPY *.mjs ./
# A new named volume copies ownership from its mount point, so both directories are prepared here.
RUN mkdir -p /data/snapshots /logs && chown -R node:node /data /logs
USER node
ENV NODE_NO_WARNINGS=1
EXPOSE 8080
ENTRYPOINT ["node", "start.mjs"]
