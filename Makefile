# Image URL to use all building/pushing image targets
IMG ?= ghcr.io/nvidia/sosreport
TAG ?= latest

# Allows for defining additional Docker buildx arguments,
# e.g. '--push'.
BUILD_ARGS ?= --load
# Architectures to build images for
BUILD_PLATFORMS ?= linux/amd64,linux/arm64


docker-build:  ## Build the Docker image
	docker buildx build \
		--platform=$(BUILD_PLATFORMS) \
		-t $(IMG):$(TAG) \
		$(BUILD_ARGS) .

docker-push:  ## Push Docker image
	docker push $(IMG):$(TAG)
