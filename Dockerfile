# ── UI build stage (Vite + React) ──
FROM node:20-alpine AS ui-build
WORKDIR /ui
COPY ui/package.json ui/package-lock.json* ./
RUN npm ci
COPY ui/ ./
RUN npm run build

# ── API build stage ──
FROM node:20-alpine AS build
WORKDIR /app

COPY package.json package-lock.json* ./
COPY sdk/package.json ./sdk/
COPY sdk/tsconfig.json ./sdk/
RUN npm ci --ignore-scripts

COPY tsconfig.json eslint.config.js vitest.config.ts ./
COPY src ./src
COPY scripts ./scripts
COPY sdk/src ./sdk/src
COPY tests ./tests

RUN npm run build
RUN npm run build:sdk

# ── Runtime stage ──
FROM node:20-alpine AS runtime
WORKDIR /app

ENV NODE_ENV=production
# Refuse to start without API_KEY unless DEV_MODE=true (enforced in code)

RUN addgroup -S app && adduser -S app -G app

COPY package.json package-lock.json* ./
COPY sdk/package.json ./sdk/
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force

COPY --from=build /app/dist ./dist
COPY --from=build /app/sdk/dist ./sdk/dist
COPY --from=ui-build /ui/dist ./ui/dist

USER app
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8000)+'/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "dist/api/server.js"]