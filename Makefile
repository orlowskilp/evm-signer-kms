.PHONY: build
build:
	cargo build $(ARGS) --release

.PHONY: doc
doc:
	cargo fmt --check
	cargo doc --no-deps --open

.PHONY: test
test:
	cargo fmt
	cargo test --lib --tests

.PHONY: test-coverage
test-coverage:
	cargo llvm-cov $(ARGS)

.PHONY: test-doc
test-doc:
	cargo test --doc

.PHONY: unit-test
unit-test:
	cargo test --lib

.PHONY: integration-tests
integration-test:
	cargo test --tests

.PHONY: clean
clean:
	cargo clean