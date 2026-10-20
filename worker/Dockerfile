FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl git && \
    curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && \
    apt-get install -y --no-install-recommends nodejs && \
    rm -rf /var/lib/apt/lists/*
ENV NODE_ENV=production WORKER_PORT=10000
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund
COPY . .
EXPOSE 10000
CMD ["node","server.js"]
