# Stage 1: Rust/Wasm Builder
FROM rust:1.75-slim as wasm-builder
WORKDIR /wasm_build
RUN apt-get update && apt-get install -y curl pkg-config libssl-dev
RUN curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
COPY ./wasm ./wasm
# Собираем Wasm модуль
RUN cd wasm && wasm-pack build --target web --out-dir ../pkg

# Stage 2: Node.js Runner
FROM node:20-alpine
WORKDIR /app
COPY frontend/package*.json ./
RUN npm install
# Копируем скомпилированный Wasm из первого этапа
COPY --from=wasm-builder /pkg ./wasm/pkg
COPY frontend/ .
EXPOSE 3000
CMD ["npm", "run", "dev"]
