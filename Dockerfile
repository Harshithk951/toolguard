FROM node:22-bookworm-slim

WORKDIR /app
COPY --chown=node:node . .

USER node
ENTRYPOINT ["node", "/app/bin/toolguard.js"]
CMD ["--help"]
