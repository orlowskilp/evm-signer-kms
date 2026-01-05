# Build the library with the specified toolchain as per `CARGO_BUILD_TARGET`
.PHONY: build
build:
	cargo build --release

# Build documentation for the library
.PHONY: doc
doc:
	cargo fmt --check
	cargo doc --no-deps

# Run all tests (no coverage)
.PHONY: test
test: fetch-public-key
	cargo test --all

# Run all examples
.PHONY: examples
examples: check-env
	@cargo run --bin tx-type-2
	@cargo run --bin tx-type-1
	@cargo run --bin tx-type-0

# Clean up
.PHONY: clean
clean:
	cargo clean

# ==== Directives for developers ====

# Run unit and integration tests and measure coverage.
# Additional flags can be passed with LLVM_COV_ARGS
.PHONY: test-coverage
test-coverage: fetch-public-key
	cargo llvm-cov $(LLVM_COV_ARGS)

# Run only documentation tests (shorthand for developers)
.PHONY: doc-test
doc-test: check-env
	cargo test --doc

# Run only unit tests (shorthand for developers)
.PHONY: unit-test
unit-test:
	cargo test --lib

# Run only integration tests (shorthand for developers)
.PHONY: integration-test
integration-test: check-env
	cargo test --tests

# ==== Helper directives ====

# Format codebase
.PHONY: format
format:
	cargo fmt
	dprint fmt

# Download and decode the public key from KMS
.PHONY: fetch-public-key
PUBLIC_KEY_FILE_PATH = $(TEST_DATA_DIR)
PUBLIC_KEY_FILE_PEM = $(PUBLIC_KEY_FILE_PATH)/$(TEST_PEM_PUB_KEY_FILE_NAME)
PUBLIC_KEY_FILE_DER = $(PUBLIC_KEY_FILE_PATH)/$(TEST_DER_PUB_KEY_FILE_NAME)
fetch-public-key: check-env
	@aws kms get-public-key \
		--region $(AWS_REGION) \
		--key-id $(KMS_KEY_ID) \
		--output text \
		--query PublicKey > $(PUBLIC_KEY_FILE_PEM) || \
		(echo "Failed to fetch public key" && exit 1)
	@cat $(PUBLIC_KEY_FILE_PEM) | base64 -d > $(PUBLIC_KEY_FILE_DER)
	@echo "Public key saved to $(PUBLIC_KEY_FILE_PEM) and decoded to $(PUBLIC_KEY_FILE_DER)"


# Lint the codebase
.PHONY: lint
lint:
	dprint check
	cargo fmt --all --check
	cargo clippy --all-targets --all-features -- -D warnings

# Check if the environment variables are set and STS token is valid
.PHONY: check-env
check-env:
ifndef KMS_KEY_ID
	$(error KMS_KEY_ID is not set)
endif
ifndef AWS_REGION
	$(error AWS_REGION is not set)
endif
	@aws --version &> /dev/null || (echo "AWS CLI not installed" && exit 1)
	@aws sts get-caller-identity &> /dev/null || \
		(echo "AWS CLI could not assume role. Did the STS token expire?" && exit 1)
	@echo "Environment variables are set and the STS token is valid"