CREATE DATABASE IF NOT EXISTS fraud_detection;
USE fraud_detection;

CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  email VARCHAR(254) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  role ENUM('ADMIN','USER') NOT NULL DEFAULT 'USER',
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at DATETIME NOT NULL
);
CREATE TABLE IF NOT EXISTS transactions (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NULL,
  account_ref VARCHAR(50) NOT NULL,
  description TEXT NOT NULL,
  amount DECIMAL(12,2) NOT NULL DEFAULT 0,
  created_at DATETIME NOT NULL,
  INDEX idx_transactions_user_created (user_id, created_at),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS suspicious_patterns (
  id INT AUTO_INCREMENT PRIMARY KEY,
  pattern_text VARCHAR(255) NOT NULL UNIQUE,
  category VARCHAR(60) NOT NULL,
  severity ENUM('LOW','MEDIUM','HIGH') NOT NULL
);
CREATE TABLE IF NOT EXISTS detection_results (
  id INT AUTO_INCREMENT PRIMARY KEY,
  transaction_id INT NOT NULL,
  pattern_id INT NOT NULL,
  algorithm VARCHAR(20) NOT NULL,
  match_count INT NOT NULL,
  positions VARCHAR(500) NOT NULL,
  risk_level ENUM('LOW','MEDIUM','HIGH') NOT NULL,
  detected_at DATETIME NOT NULL,
  FOREIGN KEY (transaction_id) REFERENCES transactions(id) ON DELETE CASCADE,
  FOREIGN KEY (pattern_id) REFERENCES suspicious_patterns(id) ON DELETE CASCADE
);

INSERT IGNORE INTO suspicious_patterns (pattern_text, category, severity) VALUES
('urgent wire transfer','Wire fraud','HIGH'),
('gift card','Scam payment','HIGH'),
('lottery winner','Advance-fee scam','HIGH'),
('verify your account','Phishing','HIGH'),
('otp','Credential theft','HIGH'),
('crypto investment','Investment scam','MEDIUM'),
('guaranteed returns','Investment scam','MEDIUM'),
('refund processing fee','Advance-fee scam','MEDIUM'),
('western union','Untraceable transfer','MEDIUM'),
('payment release fee','Advance-fee scam','HIGH'),
('wire details have changed','Business email compromise','HIGH'),
('share your password','Credential theft','HIGH'),
('remote access app','Remote-access scam','HIGH'),
('keep this transaction secret','Social engineering','HIGH'),
('pay upfront fee','Advance-fee scam','HIGH'),
('cash deposit','Untraceable transfer','MEDIUM'),
('bitcoin wallet','Crypto payment','MEDIUM'),
('tax clearance certificate','Advance-fee scam','MEDIUM'),
('investment opportunity','Investment scam','MEDIUM'),
('limited time offer','Pressure tactic','LOW'),
('act immediately','Pressure tactic','LOW'),
('prince','Advance-fee scam','LOW'),
('act now','Pressure tactic','LOW');
