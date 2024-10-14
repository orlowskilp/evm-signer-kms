.PHONY: build
build:
	cargo build $(ARGS) --release

.PHONY: doc
doc:
	cargo fmt --check
	cargo doc --no-deps --open

.PHONY: test
test:
ifndef KMS_KEY_ID
	$(error KMS_KEY_ID is not set)
endif
	cargo fmt
	cargo test --lib --tests

.PHONY: test-coverage
test-coverage:
	cargo llvm-cov $(ARGS)

.PHONY: test-doc
test-doc:
ifndef KMS_KEY_ID
	$(error KMS_KEY_ID is not set)
endif
	cargo test --doc

.PHONY: unit-test
unit-test:
	cargo test --lib

.PHONY: integration-tests
ifndef KMS_KEY_ID
	$(error KMS_KEY_ID is not set)
endif
integration-test:
	cargo test --tests

.PHONY: clean
clean:
	cargo clean