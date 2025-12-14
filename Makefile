.PHONY: install-hooks check

install-hooks:
	uv run pre-commit install

check:
	uv run pre-commit run --all-files
