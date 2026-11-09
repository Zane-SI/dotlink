# Dotlink builds two halves of one system: the Agent that runs as root and
# owns the tunnel, and the Client that only talks to it over a socket.
GO ?= go
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all build agent bar test vet fmt clean install uninstall

all: build

build: agent bar

# CGO is off everywhere: modernc.org/sqlite is pure Go, and MyGo requires a
# pure Go build, so one toolchain produces all binaries.
agent:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/dotlink-server ./cmd/dotlink-server
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/dotlink-agent ./cmd/dotlink-agent

bar:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/Dotlink.app/Contents/MacOS/dotlink-bar ./cmd/dotlink-bar
	cp packaging/macos/Info.plist bin/Dotlink.app/Contents/Info.plist

test:
	$(GO) test ./... -race -count=1

vet:
	$(GO) vet ./...

fmt:
	gofmt -l -w .

install:
	sudo packaging/macos/install.sh

uninstall:
	sudo packaging/macos/uninstall.sh

clean:
	rm -rf bin
