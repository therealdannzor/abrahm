.DEFAULT_GOAL := run
.PHONY: test

build:
	@cargo build

test:
	@cargo test

run:
	@cargo run

clean:
	@rm -rf target/ && rm -rf test/

format: clean
	@echo "Are you sure you want to remove all created data? [Y/n] "; \
	read answer; \
	if [[ $$answer = "y" || $$answer = "Y" ]]; \
	then \
		rm -rf leveldb/ && rm -f *.key; \
		echo Purged!; \
	fi





