.PHONY: build
build:
	cargo build --release

.PHONY: doc
doc:
	cargo fmt --check
	cargo doc --no-deps --open

.PHONY: test
test:
	cargo fmt
	cargo test --lib --tests

.PHONY: doc_test
doc_test:
	cargo test --doc

.PHONY: unit_test
unit_test:
	cargo test --lib

.PHONY: integration_tests
integration_test:
	cargo test --tests

.PHONY: clean
clean:
	cargo clean