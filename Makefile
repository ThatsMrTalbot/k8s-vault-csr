USE_DOCKER     ?= 1
VENDOR_ONLY    ?= 0
PACKAGE        = github.com/thatsmrtalbot/k8s-vault-csr
BINARY         = k8s-vault-csr
DOCKER_RUN     = docker run -i --rm -w /go/src/$(PACKAGE) -v $(PWD):/go/src/$(PACKAGE)
DOCKER_RUN_GO  = $(DOCKER_RUN) -e CGO_ENABLED=0 -e GOOS=$(GOOS) -e GOARCH=$(GOARCH) golang:1.10-alpine go
DOCKER_RUN_DEP = $(DOCKER_RUN) thatsmrtalbot/dep:v0.4.1
NATIVE_GO      = CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) $(shell which go)
NATIVE_DEP     = $(shell which dep)
RUN_GO         = $(if $(filter-out 0,$(USE_DOCKER)),$(DOCKER_RUN_GO),$(NATIVE_GO))
RUN_DEP        = $(if $(filter-out 0,$(USE_DOCKER)),$(DOCKER_RUN_DEP),$(NATIVE_DEP))
PLATFORMS      = linux_amd64 darwin_amd64
.DEFAULT_GOAL  := build

bin/linux_%/$(BINARY) release/linux-%-$(BINARY):   GOOS=linux
bin/darwin_%/$(BINARY) release/darwin-%-$(BINARY): GOOS=darwin
bin/%_amd64/$(BINARY) release/%-amd64-$(BINARY):   GOARCH=amd64
bin/%_arm64/$(BINARY) release/%-arm64-$(BINARY):   GOARCH=arm64
bin/%_386/$(BINARY) release/%-386-$(BINARY):       GOARCH=386
bin/%_arm/$(BINARY) release/%-arm-$(BINARY):       GOARCH=arm

vendor: Gopkg.toml
	@$(RUN_DEP) ensure -v $(if $(filter-out 0,$(VENDOR_ONLY)),-vendor-only)

bin/%/$(BINARY): vendor $(shell find $(PWD) -not -path '$(PWD)/vendor/*' -name '*.go')
	@$(RUN_GO) build -o $@ -ldflags '-X main.Version=$(VERSION) -extldflags "-static"' $(PACKAGE)/cmd/$(BINARY)

.PHONY: test
test: GOOS= 
test: GOARCH=
test: vendor
	@$(RUN_GO) test ./...

.PHONY: build
build: $(addprefix bin/,$(addsuffix /$(BINARY),$(PLATFORMS)))

.PHONY: clean
clean:	
	rm -rf bin release vendor

.SECONDEXPANSION: 
release/%: bin/$$(GOOS)-$$(GOARCH)/$(BINARY)
	@mkdir -p release
	@cp bin/$(GOOS)-$(GOARCH)/$(BINARY) release/$(GOOS)-$(GOARCH)-$(BINARY) 
