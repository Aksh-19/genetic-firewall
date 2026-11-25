.PHONY: setup test lint format run live static clean

setup:
	pip install -e ".[dev]"

test:
	python -m pytest tests/ -v

lint:
	flake8 src/ tests/ --max-line-length=100
	black --check src/ tests/

format:
	black src/ tests/

run: live

live:
	python -m src.main live

static:
	python -m src.main static

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf .pytest_cache
