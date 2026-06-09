FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/sso-api ./cmd/api

FROM alpine:3.20
RUN adduser -D -H -u 10001 appuser
WORKDIR /app
COPY --from=build /out/sso-api /app/sso-api
COPY migrations /app/migrations
USER appuser
EXPOSE 8080
ENTRYPOINT ["/app/sso-api"]
