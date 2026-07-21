# syntax=docker/dockerfile:1

FROM node:20-slim

WORKDIR /app

# Install dependencies first, separately from app code.
# This layer only rebuilds when package.json/package-lock.json change,
# so adding components/features later won't trigger a full reinstall.
COPY package*.json ./
RUN npm install

# App source is normally bind-mounted in via docker-compose for live
# editing, but we copy it here too so `docker build` alone still works
# (e.g. for a one-off demo, or in CI without compose).
COPY . .

EXPOSE 5173

CMD ["npm", "run", "dev"]
