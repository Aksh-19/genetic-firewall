.PHONY: setup test lint format run clean

setup:
	pip install -e ".[dev]"

test:
	python -m pytest tests/ -v

lint:
	flake8 src/ tests/
	black --check src/ tests/

format:
	black src/ tests/

run:
	python src/main.py

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf .pytest_cache
