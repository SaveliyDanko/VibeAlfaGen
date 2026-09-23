# Build stage
FROM golang:1.27.1-alpine AS build
ARG TARGET=proxy
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/app ./cmd/${TARGET}

# Runtime stage: non-root, no secrets.
FROM alpine:3.20
RUN adduser -D -u 10001 appuser
WORKDIR /app
RUN mkdir -p /app/runtime-secrets \
    && touch \
      /app/runtime-secrets/alfagen_encryption_key \
      /app/runtime-secrets/alfagen_internal_api_key \
      /app/runtime-secrets/alfagen_benchmark_api_key \
      /app/runtime-secrets/ca.crt \
      /app/runtime-secrets/client.crt \
      /app/runtime-secrets/client.key \
    && chmod 0755 /app/runtime-secrets \
    && chmod 0400 /app/runtime-secrets/*
COPY --from=build /out/app /app/app
COPY config.example.yaml /app/config.example.yaml
COPY config.compose.yaml /app/config.compose.yaml
USER appuser
EXPOSE 8080
ENTRYPOINT ["/app/app"]
