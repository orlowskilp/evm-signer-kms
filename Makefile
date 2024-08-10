.PHONY: build
build:
	cargo build --release

.PHONY: test
test:
	cargo fmt
	cargo test

.PHONY: unit_test
unit_test:
	cargo test unit_tests

.PHONY: integration_tests
integration_test:
	cargo test integration_tests

.PHONY: clean
clean:
	cargo clean