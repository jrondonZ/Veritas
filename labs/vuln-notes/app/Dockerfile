# INTENTIONALLY VULNERABLE LAB APP. Node built-ins only (http, node:sqlite): no npm dependencies.
FROM node:24-alpine@sha256:116b800c3754b440ee0aa3ed2f20f5bf3d99a554bfd9adeea09ea8017f6e85f5
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
