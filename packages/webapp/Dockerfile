# syntax=docker/dockerfile:1

# Build Node.js app
# ------------------------------------
FROM node:18-alpine as build
WORKDIR /app
COPY ./package*.json ./
COPY ./packages/webapp ./packages/webapp
RUN npm ci --cache /tmp/empty-cache
RUN npm run build --workspace=webapp

# Run Node.js app
# ------------------------------------
FROM node:18-alpine
ENV NODE_ENV=production

WORKDIR /app
COPY ./package*.json ./
COPY ./packages/chat-component/package.json ./packages/chat-component/
COPY ./packages/webapp/package.json ./packages/webapp/
RUN npm ci --omit=dev --workspace=webapp --cache /tmp/empty-cache
COPY --from=build app/packages/webapp/dist packages/webapp/dist
EXPOSE 3002
CMD [ "npm", "start", "--workspace=webapp" ]
