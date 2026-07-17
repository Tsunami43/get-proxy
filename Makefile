PKG := getproxy

.PHONY: run test lint check sources install clean

## run: collect and check proxies (opens the menu on a TTY)
run:
	python3 -m $(PKG)

## test: run the test suite (stdlib unittest, no dependencies)
test:
	python3 -m unittest discover -s tests -v

## sources: show the source registry
sources:
	python3 -m $(PKG) --sources

## check: quick run over http with a limit
check:
	python3 -m $(PKG) -p http -l 100

## lint: byte-compile all modules
lint:
	python3 -m compileall -q $(PKG) tests

## install: install as the getproxy console command
install:
	pip install -e .

## clean: remove caches and build artefacts
clean:
	rm -rf **/__pycache__ .pytest_cache *.egg-info build dist
