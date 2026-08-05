# syntax=docker/dockerfile:1.7
FROM node:25-trixie-slim@sha256:aabbe39553d15ede8a97cc60c9e1a97034ff772afcf696ea42b94e7f5f2ec71b AS build
WORKDIR /src
COPY package.json package-lock.json tsconfig.json ./
COPY packages ./packages
COPY admin ./admin
RUN --mount=type=cache,target=/root/.npm,sharing=locked npm ci --ignore-scripts
RUN npm run build && npm prune --omit=dev

FROM node:25-trixie-slim@sha256:aabbe39553d15ede8a97cc60c9e1a97034ff772afcf696ea42b94e7f5f2ec71b
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack && \
    rm -f /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack && \
    groupadd --system --gid 10001 shar && useradd --system --uid 10001 --gid shar --home-dir /nonexistent --shell /usr/sbin/nologin shar
WORKDIR /app
COPY --from=build /src/dist ./dist
COPY --from=build /src/node_modules ./node_modules
COPY standalone/js ./standalone/js
RUN mkdir /data && chown shar:shar /data
USER 10001:10001
ENV SHAR_LISTEN=0.0.0.0:8080 SHAR_DATABASE=/data/shar.sqlite SHAR_ADMIN_ASSETS=/app/dist/admin
EXPOSE 8080
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 CMD ["node", "/app/standalone/js/healthcheck.mjs"]
ENTRYPOINT ["node", "/app/standalone/js/server.mjs"]
