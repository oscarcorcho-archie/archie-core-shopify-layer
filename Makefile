.PHONY: test test-coverage mocks generate build clean

# Run all tests
test:
	go test ./... -v

# Run tests with coverage
test-coverage:
	go test ./... -coverprofile=coverage.out
	go tool cover -html=coverage.out -o coverage.html

# Generate GraphQL code
generate:
	go run github.com/99designs/gqlgen generate

# Build the API
build:
	go build ./cmd/api

# Build the Lambda
build-lambda:
	go build -o bin/lambda ./cmd/lambda

# Build the Worker
build-worker:
	go build -o bin/worker ./cmd/worker

# Build all services
build-all: build build-lambda build-worker

# Clean generated files
clean:
	rm -f coverage.out coverage.html
	find . -name "*_mock.go" -type f -delete

# Run linter
lint:
	golangci-lint run

# Format code
fmt:
	go fmt ./...

# Tidy dependencies
tidy:
	go mod tidy

# Run tests for application layer only
test-application:
	go test ./internal/application/... -v

# Run tests for infrastructure layer only
test-infrastructure:
	go test ./internal/infrastructure/... -v

# Run integration tests
test-integration:
	go test -tags=integration ./tests/integration/... -v

# Run all tests including integration
test-all: test test-integration

