FROM golang:1.23-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /app .

FROM gcr.io/distroless/static:nonroot
COPY --from=builder /app /app
COPY --from=builder /src/templates /templates
EXPOSE 8080
ENTRYPOINT ["/app"]
