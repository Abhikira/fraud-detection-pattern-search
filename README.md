# Detectorite (KMP / Rabin-Karp)

1. # Fraud Detection Pattern Search System


## Demo Credentials
Admin Id: arv.22139893@gmail.com
Password: 123456789


User Id: abc@gmail.com 
Password: WHr4adBKw--AytmZwNY6mWhBFzqgGg8S

## About the Project

The **Fraud Detection Pattern Search System** is a Python-based web application that identifies potentially suspicious transactions by searching transaction descriptions for predefined fraud-related keywords and phrases.

It uses two string-matching algorithms, **Knuth-Morris-Pratt (KMP)** and **Rabin-Karp**, to detect suspicious patterns efficiently. The system highlights matching phrases, records their positions, assigns risk levels, and stores detection results in a database.

## Algorithms Used

### 1. KMP Algorithm
- Uses the Longest Prefix Suffix (LPS) array.
- Avoids unnecessary character comparisons.
- Time Complexity: O(n + m).

### 2. Rabin-Karp Algorithm
- Uses hashing and the rolling hash technique.
- Verifies character matches to handle hash collisions.
- Average Time Complexity: O(n + m).
- Worst-case Time Complexity: O(n × m).

Both algorithms support case-insensitive matching and multiple occurrences.

## Key Features

- Manual transaction entry.
- CSV file upload for bulk analysis.
- Selection between KMP and Rabin-Karp.
- Detection of multiple suspicious phrases.
- Display of matched phrases and their positions.
- LOW, MEDIUM and HIGH risk classification.
- User authentication and admin functionality.
- Dashboard for reviewing previous detection results.
- Database storage of transactions and detection history.

## Technology Stack

| Technology | Purpose |
|---|---|
| Python | Backend and algorithms |
| Flask | Web framework |
| HTML, CSS, JavaScript | Frontend |
| MySQL / SQLite | Database |
| SQL | Database management |
| CSV | Bulk transaction input |

## Database Tables

- **Users:** Stores user and authentication details.
- **Transactions:** Stores transaction information.
- **Suspicious Patterns:** Stores predefined fraud-related phrases, categories and severity.
- **Detection Results:** Stores matched patterns, positions, selected algorithm and risk levels.

## How It Works

1. User enters transaction details or uploads a CSV file.
2. The system retrieves suspicious patterns from the database.
3. User selects KMP or Rabin-Karp.
4. The selected algorithm searches transaction descriptions.
5. Matching phrases and their positions are identified.
6. A risk level is assigned based on detected patterns.
7. Results are stored and displayed on the dashboard.




## Installation

```bash
git clone https://github.com/gouravjonwal/fraud-detection-pattern-search.git

cd fraud-detection-pattern-search

python -m venv .venv

.venv\Scripts\activate

pip install -r requirements.txt

python app.py
```

Open in your browser:

`http://127.0.0.1:5000`

Configure the required environment variables and database settings before running the application.

## Limitations

- Detection depends on predefined suspicious phrases.
- Unknown fraud patterns may not be detected.
- A matching phrase does not necessarily prove fraud.
- The system uses rule-based detection, not machine learning.

## Future Scope

- Machine-learning-based fraud detection.
- Natural Language Processing (NLP).
- Real-time transaction monitoring.
- Advanced fraud analytics and reporting.

## Conclusion

This project demonstrates the practical application of KMP and Rabin-Karp string-matching algorithms in transaction analysis, combining concepts of Algorithm Design and Analysis (ADA) and Database Management Systems (DBMS).