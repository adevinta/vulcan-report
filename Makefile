GOPATH=$(shell go env GOPATH)
GOBIN=$(GOPATH)/bin
GOSRC=$(GOPATH)/src

$(GOBIN)/golangci-lint:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.46.0

.PHONY: test
test:
	go test -v -short -coverprofile=coverage.txt -covermode=atomic ./...

.PHONY: lint
lint: $(GOBIN)/golangci-lint
	$(GOBIN)/golangci-lint run

.PHONY: fmt
fmt:
	find ./ -name "*.proto" | xargs clang-format -i

.PHONY: build
build:
	go build .
