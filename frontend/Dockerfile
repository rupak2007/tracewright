# Web UI: build with Node, serve with unprivileged Nginx (SEC-07). Pinned by tag (digests: P9).
FROM node:24.14-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY tsconfig.json vite.config.ts index.html ./
COPY src ./src
RUN npm run build

FROM nginxinc/nginx-unprivileged:1.29-alpine AS web
COPY nginx.conf /etc/nginx/nginx.conf
COPY security-headers.conf /etc/nginx/security-headers.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 8080
