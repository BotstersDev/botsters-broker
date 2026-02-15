FROM node:22-slim

WORKDIR /app

# Install dependencies for better-sqlite3
RUN apt-get update && apt-get install -y python3 make g++ && rm -rf /var/lib/apt/lists/*

COPY package.json package-lock.json* ./
RUN npm ci --production=false

COPY tsconfig.json schema.sql ./
COPY src/ ./src/

RUN npm run build

# Remove dev dependencies
RUN npm prune --production

# Create data directory
RUN mkdir -p /app/data

ENV NODE_ENV=production
ENV HTTP_PORT=8787
ENV DB_PATH=/app/data/broker.db

EXPOSE 8787

CMD ["node", "dist/index.js"]
