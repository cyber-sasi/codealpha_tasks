# SecureReview Demo — CodeAlpha Task 3

A small, local-only Flask project for practicing a secure coding review. It pairs an intentionally insecure teaching application with a remediated implementation, tests, Bandit scans, and a source-backed security report.

## Objective

Review a deliberately limited Flask application using manual source inspection, Bandit static analysis, and pytest. Understand how common coding mistakes create risk, then compare them with practical remediations.

## Features

- Home, registration, login, profile, search, and feedback pages.
- SQLite storage initialized automatically when either app starts.
- Separate `vulnerable_app/` and `secure_app/` implementations.
- Tests for both applications and important input/security behaviors.
- A structured report at [`reports/security_review.md`](reports/security_review.md).

## Technology stack

- Python 3.11+
- Flask
- SQLite (`sqlite3` from the Python standard library)
- pytest
- Bandit

## Project structure

```text
Task-3-Secure-Coding-Review/
├── vulnerable_app/
│   ├── __init__.py
│   ├── app.py
│   └── templates/
├── secure_app/
│   ├── __init__.py
│   ├── app.py
│   └── templates/
├── tests/
│   ├── conftest.py
│   ├── test_secure_app.py
│   └── test_vulnerable_app.py
├── reports/
│   └── security_review.md
├── screenshots/
│   └── README.md
├── requirements.txt
├── .gitignore
└── README.md
```

## Setup

Open a terminal in the project directory. Python 3.11 or newer is required.

### Create and activate a virtual environment

Windows PowerShell:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Windows Command Prompt:

```bat
py -3.11 -m venv .venv
.venv\Scripts\activate.bat
```

macOS/Linux:

```sh
python3 -m venv .venv
source .venv/bin/activate
```

### Install dependencies

```sh
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Run either application locally

Run only one implementation at a time. Both bind to loopback (`127.0.0.1`); neither makes outbound network requests.

Vulnerable teaching version:

```sh
python -m vulnerable_app.app
```

Remediated version:

```sh
python -m secure_app.app
```

Open the local URL printed by Flask (normally `http://127.0.0.1:5000`). The vulnerable version is intentionally unsafe and should only be used on a trusted local machine with synthetic data. Do not expose it to a network.

For the secure app, set `SECURE_REVIEW_SECRET_KEY` to a long random value when using it beyond a short local demonstration. If unset, a fresh random development key is generated at startup, so sessions do not survive a restart.

## Run tests

```sh
python -m pytest -q
```

The tests use temporary SQLite files and Flask's in-process test client; they do not start a network listener.

## Run Bandit

Scan both apps:

```sh
python -m bandit -r vulnerable_app
python -m bandit -r secure_app
```

Bandit reports static patterns, not proof of exploitability. Read the report's verification notes and inspect each flagged source location before drawing conclusions.

## Read the security report

See [`reports/security_review.md`](reports/security_review.md) for the scope, methodology, findings and evidence, severities, remediation mapping, analysis limitations, and secure coding recommendations.

## Security and ethical notice

This is an educational secure-coding demonstration, not a production service or a penetration-testing tool. The vulnerable implementation intentionally contains local-only insecure examples. Use synthetic data, do not expose it, and do not reuse any demo passwords. Do not use this project against external websites or systems.

## Limitations

The application is intentionally small and does not provide production account recovery, email verification, rate limiting, a deployment server, or a full production CSRF/authentication framework. The secure implementation demonstrates basic defensive patterns, not a substitute for a full threat model or professional security assessment.

## Conclusion

Compare the source and behavior of the two apps, reproduce the checks locally, and use the report as a guide to recognize and remediate common web application coding risks.
