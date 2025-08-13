# use 22 version as i put it in .nvmrc
FROM node:22-bookworm-slim

# /app is just convention -> telling when in container, run all commands in app dir
WORKDIR /app

# first copy all pkg.json and pkg-lock.json -> so we can install deps
COPY package*.json ./

# install deps ci stands for clean install -> install deps with exact version from pkg.json & pkg-lock.json
RUN npm ci

# COPY src code -> curr dir ./ where Dockerfile is written, to curr container dir /app by ./
COPY . .

# to start up server -> written in pkg.json scripts, separated in arr like args, npm run dev -> ["npm", "run", "dev"]
# pass "--", "--host" so to pass command as for hot module reload
# CMD ["npm", "run", "dev", "--", "--host"] # added this in compose file
