# nomad-netblock: static Go binary + nftables. Run with cap_add = ["net_admin"] only (never privileged).
FROM --platform=$BUILDPLATFORM golang:1.22-alpine AS build
ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod *.go ./
RUN go vet ./... && CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /netblock .
FROM alpine:3.22
RUN apk add --no-cache nftables
COPY --from=build /netblock /usr/local/bin/netblock
ENTRYPOINT ["/usr/local/bin/netblock"]
