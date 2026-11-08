# PhishGuard CI Agent API

Minimal local P0 foundation for the PhishGuard CI Agent.

## Requirements

- Python 3.12
- Git

## Setup

    py -3.12 -m venv .venv
    .\.venv\Scripts\Activate.ps1
    python -m pip install --upgrade pip
    python -m pip install -e ".[dev]"
    Copy-Item .env.example .env

Configuration is read from environment variables prefixed with PHISHGUARD_.
The example values are non-secret defaults.

## Run

    uvicorn app.main:app --reload

The liveness endpoint is GET /health.

## Quality checks

    ruff check .
    mypy app
    pytest
    gitleaks detect --source . --no-git

The CI workflow runs Ruff, mypy, pytest, and Gitleaks on GitHub Actions.

## Scope

P0 contains only the API foundation and its checks. Scoring, external providers,
Hermes/LLM calls, database schemas, and frontend code are outside this implementation.
