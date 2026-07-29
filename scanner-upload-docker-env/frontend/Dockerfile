FROM node:20-alpine

WORKDIR /app

# Install dependencies first so this layer is cached and doesn't reinstall
# on every source change (docker-compose then bind-mounts the rest of the
# folder over this for live editing — see docker-compose.yml comments).
COPY package.json package-lock.json ./
RUN npm ci

COPY . .

EXPOSE 5173

CMD ["npm", "run", "dev"]
