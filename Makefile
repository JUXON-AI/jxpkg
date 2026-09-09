GO ?= go

.PHONY: check test test-race build clean

check:
	@test -z "$$(find . -path ./.git -prune -o -path ./vendor -prune -o \
		-name '*.go' -type f -print0 | xargs -0 gofmt -l)"
	$(GO) vet ./...
	$(GO) mod verify
	$(GO) list -mod=vendor ./... >/dev/null

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

build:
	$(GO) test -run '^$$' ./...

clean:
	$(GO) clean -testcache
