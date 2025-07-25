FROM golang:1.24 AS build

WORKDIR /plugin

COPY api cilium/api
COPY go.mod cilium/go.mod
COPY go.sum cilium/go.sum

COPY examples/datapath-plugin/go.mod \
     examples/datapath-plugin/go.sum \
     examples/datapath-plugin/*.go \
     examples/datapath-plugin/*.o \
     ./

RUN CGO_ENABLED=0 GOOS=linux go build -o /datapath-plugin

FROM ubuntu:22.04 AS release

COPY --from=build /datapath-plugin /datapath-plugin

ENTRYPOINT ["/datapath-plugin"]

