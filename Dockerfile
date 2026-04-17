# Build from the parent directory so the replace directive can resolve:
#   docker build -f emailanalyzer-web/Dockerfile -t emailanalyzer-web .
#
# On Railway: once emailanalyzer is published to GitHub, remove the replace
# directive in go.mod and build with the standard Railway Dockerfile flow.

FROM golang:1.23-alpine AS builder
WORKDIR /build

# Copy the sibling core library (needed for the replace directive)
COPY emailanalyzer/ ../emailanalyzer/

# Copy web app sources
COPY emailanalyzer-web/go.mod emailanalyzer-web/go.sum ./
RUN go mod download

COPY emailanalyzer-web/ .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /app .

FROM gcr.io/distroless/static:nonroot
COPY --from=builder /app /app
COPY --from=builder /build/templates /templates
EXPOSE 8080
ENTRYPOINT ["/app"]
