# nomad-netblock v0.3: static Go binary + nftables. Run with cap_add = ["net_admin"] only (never privileged).
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod *.go ./
RUN go vet ./... && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=0.3.1" -o /netblock .
FROM alpine:3.22
RUN apk add --no-cache nftables
COPY --from=build /netblock /usr/local/bin/netblock
ENTRYPOINT ["/usr/local/bin/netblock"]
