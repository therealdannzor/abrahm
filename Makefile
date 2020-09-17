.DEFAULT_GOAL := run

build:
	@cargo build

test:
	@cargo test

run:
	@cargo run

clean:
	@rm -rf target/

format: clean
	@echo "Are you sure you want to remove all created data? [Y/n] "; \
	read answer; \
	if [[ $$answer = "y" || $$answer = "Y" ]]; \
	then \
		rm -rf leveldb/ && rm -f *.key; \
		echo Purged!; \
	fi





