# Include variables
include .env.dist
-include .env
export

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOMOD=$(GOCMD) mod
GOTEST=$(GOCMD) test
GOFLAGS := -v 
LDFLAGS := -s -w
    
all: build
build:
	$(GOBUILD) $(GOFLAGS) -ldflags '$(LDFLAGS)' -o "naabu-probe" cmd/naabu/main.go
test: 
	$(GOTEST) $(GOFLAGS) ./...
tidy:
	$(GOMOD) tidy