# Getting started

## Local setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e ".[dev]"
pytest
```

## Run demos

Federated demo:

```bash
python -m evidenceos.examples.federated_demo
```
