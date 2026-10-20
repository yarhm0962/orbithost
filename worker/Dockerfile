FROM node:24-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends docker.io git ca-certificates && rm -rf /var/lib/apt/lists/*
ENV NODE_ENV=production WORKER_PORT=8787
WORKDIR /srv/worker
COPY package*.json ./
RUN npm install --omit=dev && npm cache clean --force
COPY worker ./worker
EXPOSE 8787
CMD ["node", "worker/server.js"]
