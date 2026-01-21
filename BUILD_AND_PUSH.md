# EvidenceOS — Local build and push checklist

This repo is designed for **local VS Code** development without requiring Copilot.

## 1) Clone your empty private repo

```bash
git clone <YOUR_GITHUB_REPO_URL>
cd evidenceos
```

## 2) Unpack this zip into the repo folder

Unzip into the repo root (so README.md, pyproject.toml are at the top).

## 3) Create a virtual environment and install

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -U pip
pip install -e ".[dev]"
```

## 4) Run checks

```bash
pytest
ruff check .
mypy src
mkdocs build
```

## 5) Commit and push

```bash
git add .
git commit -m "Initial EvidenceOS kernel (ledger/oracles/capsules/ETL/federation)"
git push -u origin main
```

## 6) Optional: run docs locally

```bash
mkdocs serve
```

Generated: 2026-01-21
