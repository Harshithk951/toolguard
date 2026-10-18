FROM node:22-bookworm-slim

WORKDIR /app
COPY --chown=node:node . .

USER node
CMD ["node", "bin/toolguard.js", "--help"]
