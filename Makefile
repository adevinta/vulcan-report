GOPATH=$(shell go env GOPATH)
GOBIN=$(GOPATH)/bin
GOSRC=$(GOPATH)/src

$(GOBIN)/golangci-lint:
	curl -sfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh| sh -s -- -b $(GOBIN) v1.36.0

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
