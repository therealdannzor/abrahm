.DEFAULT_GOAL := run
.PHONY: test

build:
	@cargo build

test:
	@cargo test

testd:
	@cargo test -- --color always --show-output

run:
	@cargo run

clean:
	@rm -rf keys/* && rm -rf database/
