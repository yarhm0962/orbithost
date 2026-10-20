FROM node:24-bookworm-slim
ENV NODE_ENV=production PORT=8080 DATABASE_PATH=/data/orbithost.sqlite UPLOAD_DIR=/data/uploads
WORKDIR /srv/orbithost
COPY package*.json ./
RUN npm install --omit=dev && npm cache clean --force && mkdir -p /data && chown -R node:node /data
COPY src ./src
COPY public ./public
USER node
EXPOSE 8080
CMD ["node", "src/server.js"]
