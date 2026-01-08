# Makefile

PYTHON = python3
SCRIPT = proxy.py
CONFIG = config.ini

.PHONY: run check clean

check:
	@echo "Checking Python syntax..."
	$(PYTHON) -m py_compile $(SCRIPT)

run:
	@echo "Starting proxy server..."
	$(PYTHON) $(SCRIPT)

clean:
	@echo "Cleaning compiled files..."
	rm -rf __pycache__ *.pyc
