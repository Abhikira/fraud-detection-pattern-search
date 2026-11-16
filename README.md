# Detectorite (KMP / Rabin-Karp)

1. In PowerShell, create and activate a virtual environment, then install dependencies:
   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   python -m pip install -r requirements.txt
   ```
2. Copy `.env.example` to `.env` and set a private, random `FLASK_SECRET_KEY`. The app loads this file at startup; never commit `.env`.
3. Run `python app.py` from the activated environment → open http://127.0.0.1:5000

SQLite is the default and requires no separate service or password. The app creates `instance/fraud_detection.sqlite3`, its tables, and the starter phrase library automatically when the database is first used.

To use MySQL instead, set `DB_ENGINE=mysql` in `.env`, configure `DB_HOST`, `DB_USER`, `DB_PASSWORD`, and `DB_NAME`, and initialize the schema from PowerShell with `cmd /c "mysql -u root -p < schema.sql"`.

Create an account with the configured admin email to receive the administrator role. Other accounts may register with Gmail or Proton addresses. Passwords must be 8 to 128 characters and are stored as salted hashes. Email addresses are not verified. Transaction records are scoped to their owning user; the administrator can activate or suspend accounts and add, edit, or delete shared suspicious phrases, but cannot read other users' transactions.

For an existing MySQL database created with the earlier `transaction_text`, `algorithm_used`, and `match_position` columns, apply each migration once, in order:

1. `cmd /c "mysql -u root -p < migrations/001_legacy_schema_column_names.sql"`
2. `cmd /c "mysql -u root -p < migrations/002_user_accounts.sql"`

These migrations apply only to existing MySQL databases; SQLite setup is automatic.

The app uses KMP and Rabin-Karp phrase matching; it does not train a machine-learning model. Privacy and Terms pages are available at `/privacy` and `/terms`.

## Before exposing an installation

Email ownership is not verified and sign-in is not rate-limited. Do not expose the app publicly until email verification, rate limiting, HTTPS, a persistent session secret, and organization-specific legal notices are configured. Restrict access to trusted users.

Detection results are text-match signals for human review, not proof of fraud. Use authorized data only and verify consequential decisions independently.
