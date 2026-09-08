GO ?= go

.PHONY: build

build:
	$(GO) test -run '^$$' ./...
