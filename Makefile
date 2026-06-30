.PHONY: install dev test lint demo sales-demo init-db serve docker

install:
	pip install -e .

dev:
	pip install -e ".[api,sql,dev]"

test:
	pytest -q

lint:
	ruff check earned_autonomy tests

demo:
	python -m earned_autonomy.cli demo

sales-demo:
	python -m earned_autonomy.cli sales-demo

init-db:
	python -m earned_autonomy.cli init-db

serve:
	python -m earned_autonomy.cli serve --host 0.0.0.0 --port 8000

docker:
	docker compose up --build
