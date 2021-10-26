# Build the binary
FROM golang:1.17.2 as builder

WORKDIR /workspace

# Copy the go source
COPY . .

# Build
ENV GOPROXY https://goproxy.cn
ENV GO111MODULE on
ENV CGO_ENABLED 0
ENV GOOS linux
ENV GOARCH amd64
RUN go build -o bin/psh ./cmd/psh

FROM alpine:3.13
WORKDIR /
COPY --from=builder /workspace/bin/psh .

ENTRYPOINT ["/psh"]
