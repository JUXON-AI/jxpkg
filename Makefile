GO ?= go

.PHONY: fmt-check vet compile test vendor-check

fmt-check:
	@test -z "$$(gofmt -l $$(git ls-files '*.go' ':!vendor/**'))"

vet:
	$(GO) vet ./...

compile:
	$(GO) test -run '^$$' ./...

test:
	$(GO) test ./...

vendor-check:
	$(GO) mod verify
	$(GO) list -mod=vendor ./...
