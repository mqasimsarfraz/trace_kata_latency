SHELL := /bin/bash

GADGET_NAME ?= trace_kata_latency
GADGET_TAG ?= latest
GADGET_REPOSITORY ?= ghcr.io/mqasimsarfraz
GADGET_IMAGE := $(GADGET_REPOSITORY)/$(GADGET_NAME):$(GADGET_TAG)

BUILDER_IMAGE ?= ghcr.io/inspektor-gadget/gadget-builder:main
DOCKER ?= docker
IG ?= ig
SUDO ?= sudo
SUDO_ENV := $(if $(strip $(SUDO)),$(SUDO) -E)
GADGET_BUILD_PARAMS ?=
IG_FLAGS ?=

.PHONY: all build pull-builder-image push push-existing

all: build

pull-builder-image:
	$(DOCKER) pull $(BUILDER_IMAGE)

build: pull-builder-image
	@echo "Building $(GADGET_IMAGE)"
	$(SUDO_ENV) $(IG) image build \
		--builder-image $(BUILDER_IMAGE) \
		--builder-image-pull=never \
		-t $(GADGET_IMAGE) \
		$(GADGET_BUILD_PARAMS) \
		.

push: build
	@echo "Pushing $(GADGET_IMAGE)"
	$(SUDO_ENV) $(IG) image push $(GADGET_IMAGE) $(IG_FLAGS)

push-existing:
	@echo "Pushing existing $(GADGET_IMAGE)"
	$(SUDO_ENV) $(IG) image push $(GADGET_IMAGE) $(IG_FLAGS)
