# Detectorite - Transaction Review

Detectorite is a web application for reviewing transaction descriptions against a library of suspicious phrases. It highlights matching phrases, records detections, and assigns a risk level from the matched phrase severities. It is an assistive screening tool, not proof that a transaction is fraudulent.

## Features

- Scan a transaction description or upload a CSV with `account_ref` and `description` columns. An `amount` column is optional.
- Choose either KMP or Rabin-Karp string matching.
- Review the risk level, matched phrases, categories, and match positions in a popup after a scan.
- View transaction and detection history in a dashboard.
- Administrators can manage the shared phrase library and user accounts.
- SQLite is the default database; MySQL is also supported.

## Algorithms

Both algorithms perform case-insensitive exact substring matching. They search each transaction description for each phrase in the library; they do not train a machine-learning model.

- **Knuth-Morris-Pratt (KMP):** Builds a longest-prefix-suffix table for each phrase. When a character differs, it uses that table to continue without rechecking already matched text. Its search time is O(n + m) per phrase, where `n` is the description length and `m` is the phrase length. KMP is useful when reliable, predictable matching time matters.
- **Rabin-Karp:** Uses a rolling hash to compare each possible substring with a phrase, then verifies hash matches character by character to avoid collision errors. It is useful for substring search and demonstrates hash-based matching; hash collisions can make its worst-case time O(n * m) per phrase.

The application's risk level is based on the severity of matched phrases. Three or more matches escalate the overall level to HIGH. Matching results can include false positives or miss fraud phrased differently; a person should review them before taking action.

## Applications

The project can be used as a learning example for string-search algorithms, as a prototype for reviewing suspicious payment messages, or as a starting point for internal transaction-triage tools. Any real deployment should use organization-approved rules and authorized data, and should not make consequential decisions solely from phrase matches.

## Run locally

1. Create a virtual environment and install dependencies:

   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   python -m pip install -r requirements.txt
   ```
2. Copy `.env.example` to `.env` and set a private, random `FLASK_SECRET_KEY`.
3. Run the application:

   ```powershell
   python app.py
   ```
4. Open <http://127.0.0.1:5000>.

Flask serves both the frontend and backend. With the default SQLite configuration, the app creates its database and seeds the phrase library automatically.

### MySQL

Set `DB_ENGINE=mysql`, `DB_HOST`, `DB_USER`, `DB_PASSWORD`, and `DB_NAME` in `.env`, then initialize the schema and add the extra starter phrases:

```powershell
cmd /c "mysql -u root -p < schema.sql"
cmd /c "mysql -u root -p < migrations/003_add_fraud_phrases.sql"
```

For an existing database made with earlier column names, apply migrations `001_legacy_schema_column_names.sql` and `002_user_accounts.sql` first, in that order. Apply migration `003_add_fraud_phrases.sql` afterward. The phrase migration uses `INSERT IGNORE`, so it can be safely re-run without duplicating phrases.

## Safety and privacy

The starter phrase list is a set of examples, not a complete or authoritative fraud taxonomy. Review and tailor it before use. Account records are scoped to their owners. Email addresses are not verified and sign-in is not rate-limited; do not expose an installation publicly until suitable authentication controls, HTTPS, a persistent secret key, and organization-specific legal notices are in place.

Privacy and Terms pages are available in the application. Use only data you are authorized to process.
