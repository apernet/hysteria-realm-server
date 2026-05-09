FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/hysteria-realm-server

FROM scratch
COPY --from=builder /out/hysteria-realm-server /hysteria-realm-server
USER 65532:65532
EXPOSE 8443
ENTRYPOINT ["/hysteria-realm-server"]
