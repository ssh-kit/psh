export GO111MODULE ?= on
export GOPROXY ?= https://goproxy.cn

GIT_VERSION := $(shell git describe --always --tags)
BASE_PACKAGE_NAME := github.com/ssh-kit/psh
DEFAULT_LDFLAGS := "-X $(BASE_PACKAGE_NAME).Version=$(GIT_VERSION)"
IMG := hypnostsang/psh:$(GIT_VERSION)

all:

# Run tests
test: fmt vet
	go test ./... -coverprofile cover.out

# Build psh binary
psh: fmt vet
	go build -ldflags=$(DEFAULT_LDFLAGS) -o bin/psh ./cmd/psh

# Run psh
run: fmt vet
	go run ./cmd/psh \
		-config-dir ./.psh \
		-verbose 2

# Run go fmt against code
fmt:
	go fmt ./...

# Run go vet against code
vet:
	go vet ./...

# Build the docker image
docker-build: test
	docker build . -t ${IMG}

# Push the docker image
docker-push:
	docker push ${IMG}