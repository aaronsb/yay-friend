# yay-friend build targets.
#
# The version label is derived from git rather than written down. A hardcoded
# VERSION is a number that stops being true the commit after someone edits it,
# and `yay-friend version` is what a user reports a bug against.
#
# Override anything on the command line: `make build VERSION=1.2.3`.

BINARY      := yay-friend
PKG         := ./cmd/yay-friend
MODULE      := github.com/aaronsb/yay-friend
VERSION_PKG := $(MODULE)/internal/version

# v0.2.0 exactly on the tag; v0.2.0-3-gabc1234 three commits later; the bare
# short hash before the first tag ever exists. -dirty when the tree has edits,
# because a binary built from uncommitted code should say so.
#
# The fallback is a second assignment rather than a `|| echo dev` inside the
# pipeline: the shell's `||` sees the exit status of `sed`, which is 0 even when
# git printed nothing, so the fallback never fired and a build outside a git
# checkout -- a release tarball, a distro build -- linked an empty version
# string.
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null | sed 's/^v//')
VERSION    := $(if $(strip $(VERSION)),$(VERSION),dev)
GIT_COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
# SOURCE_DATE_EPOCH is honored so a distro build can be reproducible.
BUILD_DATE ?= $(shell date -u -d "@$${SOURCE_DATE_EPOCH:-$$(date +%s)}" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X $(VERSION_PKG).Version=$(VERSION) \
	-X $(VERSION_PKG).GitCommit=$(GIT_COMMIT) \
	-X $(VERSION_PKG).BuildDate=$(BUILD_DATE)

GO       ?= go
GOFLAGS  ?= -trimpath
PREFIX   ?= $(HOME)/.local
DESTDIR  ?=

.PHONY: all build install uninstall test vet fmt fmt-check check clean version help

all: build

## build: compile the binary with version information
build:
	$(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(BINARY) $(PKG)

## install: build and install to $(PREFIX)/bin
install: build
	install -Dm755 $(BINARY) $(DESTDIR)$(PREFIX)/bin/$(BINARY)
	@echo "installed $(DESTDIR)$(PREFIX)/bin/$(BINARY) ($(VERSION))"
	@command -v pacman >/dev/null 2>&1 && pacman -Qq yay-friend-git >/dev/null 2>&1 && \
		echo "note: yay-friend-git is also installed; \
this copy shadows /usr/bin/$(BINARY) if $(PREFIX)/bin precedes it on PATH" || true

## uninstall: remove an installed binary
uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(BINARY)

## test: run the test suite
test:
	$(GO) test ./...

## vet: run go vet
vet:
	$(GO) vet ./...

## fmt: rewrite sources with gofmt
fmt:
	gofmt -w $$($(GO) list -f '{{.Dir}}' ./...)

## fmt-check: fail if anything is unformatted
fmt-check:
	@unformatted=$$(gofmt -l $$($(GO) list -f '{{.Dir}}' ./...)); \
	if [ -n "$$unformatted" ]; then \
		echo "unformatted files:"; echo "$$unformatted"; exit 1; \
	fi

## check: everything CI would run
check: fmt-check vet test

## version: print the version this build would carry
version:
	@echo "version    $(VERSION)"
	@echo "commit     $(GIT_COMMIT)"
	@echo "build date $(BUILD_DATE)"

## clean: remove build output
clean:
	rm -f $(BINARY)

## help: list targets
help:
	@grep -hE '^## ' $(MAKEFILE_LIST) | sed 's/^## /  /'
