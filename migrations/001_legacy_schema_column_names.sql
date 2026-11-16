USE fraud_detection;

ALTER TABLE transactions
  CHANGE COLUMN transaction_text description TEXT NOT NULL;

ALTER TABLE detection_results
  CHANGE COLUMN algorithm_used algorithm VARCHAR(50) NOT NULL,
  CHANGE COLUMN match_position positions VARCHAR(500) NOT NULL;

UPDATE suspicious_patterns SET severity = UPPER(severity);
UPDATE detection_results SET risk_level = UPPER(risk_level);
