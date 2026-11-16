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

INSERT IGNORE INTO suspicious_patterns
(pattern_text, category, severity)
VALUES

-- 1. Credential Theft and OTP Scams
('otp', 'Credential theft', 'HIGH'),
('share your password', 'Credential theft', 'HIGH'),
('share your pin', 'Credential theft', 'HIGH'),
('enter your pin', 'Credential theft', 'HIGH'),
('send your otp', 'Credential theft', 'HIGH'),
('confirm your otp', 'Credential theft', 'HIGH'),
('banking password', 'Credential theft', 'HIGH'),
('login credentials', 'Credential theft', 'HIGH'),
('account credentials', 'Credential theft', 'HIGH'),
('reset your password', 'Credential theft', 'MEDIUM'),
('verify your identity', 'Identity theft', 'MEDIUM'),
('provide your aadhaar', 'Identity theft', 'HIGH'),
('share your pan card', 'Identity theft', 'HIGH'),

-- 2. Phishing and Account Scams
('verify your account', 'Phishing', 'HIGH'),
('account suspended', 'Phishing', 'HIGH'),
('account blocked', 'Phishing', 'HIGH'),
('account will be closed', 'Phishing', 'HIGH'),
('click this link', 'Phishing', 'MEDIUM'),
('update your bank details', 'Phishing', 'HIGH'),
('confirm your bank details', 'Phishing', 'HIGH'),
('kyc update required', 'Phishing', 'HIGH'),
('kyc verification pending', 'Phishing', 'HIGH'),
('your account has been compromised', 'Phishing', 'HIGH'),
('unusual login detected', 'Phishing', 'MEDIUM'),
('unauthorized login attempt', 'Phishing', 'HIGH'),
('secure your account', 'Phishing', 'MEDIUM'),

-- 3. Banking and Payment Fraud
('urgent wire transfer', 'Wire fraud', 'HIGH'),
('wire details have changed', 'Business email compromise', 'HIGH'),
('transfer money immediately', 'Wire fraud', 'HIGH'),
('send money urgently', 'Wire fraud', 'HIGH'),
('payment release fee', 'Advance-fee scam', 'HIGH'),
('refund processing fee', 'Advance-fee scam', 'MEDIUM'),
('cash deposit', 'Untraceable transfer', 'MEDIUM'),
('western union', 'Untraceable transfer', 'MEDIUM'),
('money transfer pending', 'Payment fraud', 'MEDIUM'),
('failed transaction refund', 'Payment fraud', 'MEDIUM'),
('beneficiary account changed', 'Wire fraud', 'HIGH'),
('new bank account details', 'Wire fraud', 'HIGH'),
('unexpected payment request', 'Payment fraud', 'MEDIUM'),
('send money to this account', 'Payment fraud', 'HIGH'),
('payment confirmation required', 'Payment fraud', 'MEDIUM'),

-- 4. Lottery and Prize Scams
('lottery winner', 'Advance-fee scam', 'HIGH'),
('claim your prize', 'Advance-fee scam', 'HIGH'),
('you have won a prize', 'Advance-fee scam', 'HIGH'),
('congratulations you won', 'Advance-fee scam', 'MEDIUM'),
('prize money transfer', 'Advance-fee scam', 'HIGH'),
('processing fee required', 'Advance-fee scam', 'HIGH'),
('winning amount', 'Advance-fee scam', 'MEDIUM'),
('lucky draw winner', 'Advance-fee scam', 'HIGH'),
('claim your reward', 'Advance-fee scam', 'MEDIUM'),
('free gift voucher', 'Advance-fee scam', 'MEDIUM'),

-- 5. Investment and Cryptocurrency Scams
('crypto investment', 'Investment scam', 'MEDIUM'),
('guaranteed returns', 'Investment scam', 'MEDIUM'),
('double your money', 'Investment scam', 'HIGH'),
('risk free investment', 'Investment scam', 'HIGH'),
('daily profit guaranteed', 'Investment scam', 'HIGH'),
('investment opportunity', 'Investment scam', 'MEDIUM'),
('bitcoin wallet', 'Crypto payment', 'MEDIUM'),
('crypto wallet transfer', 'Crypto payment', 'MEDIUM'),
('send cryptocurrency', 'Crypto payment', 'HIGH'),
('instant investment returns', 'Investment scam', 'HIGH'),
('limited investment slots', 'Investment scam', 'MEDIUM'),
('high profit guaranteed', 'Investment scam', 'HIGH'),
('crypto trading scheme', 'Investment scam', 'MEDIUM'),

-- 6. Job and Employment Scams
('registration fee for job', 'Job scam', 'HIGH'),
('pay to get a job', 'Job scam', 'HIGH'),
('work from home registration fee', 'Job scam', 'HIGH'),
('job offer fee', 'Job scam', 'HIGH'),
('earn money from home', 'Job scam', 'LOW'),
('no experience required', 'Job scam', 'LOW'),
('salary processing fee', 'Job scam', 'HIGH'),
('interview selection fee', 'Job scam', 'HIGH'),
('training fee required', 'Job scam', 'MEDIUM'),

-- 7. Social Engineering and Pressure Tactics
('keep this transaction secret', 'Social engineering', 'HIGH'),
('act immediately', 'Pressure tactic', 'LOW'),
('act now', 'Pressure tactic', 'LOW'),
('limited time offer', 'Pressure tactic', 'LOW'),
('do not tell anyone', 'Social engineering', 'HIGH'),
('confidential transaction', 'Social engineering', 'MEDIUM'),
('emergency money transfer', 'Social engineering', 'HIGH'),
('immediate action required', 'Pressure tactic', 'MEDIUM'),
('offer expires today', 'Pressure tactic', 'LOW'),
('urgent payment required', 'Pressure tactic', 'HIGH'),
('do not contact your bank', 'Social engineering', 'HIGH'),

-- 8. Remote Access Scams
('remote access app', 'Remote-access scam', 'HIGH'),
('install anydesk', 'Remote-access scam', 'HIGH'),
('install teamviewer', 'Remote-access scam', 'HIGH'),
('share your screen', 'Remote-access scam', 'HIGH'),
('enable screen sharing', 'Remote-access scam', 'HIGH'),
('download this application', 'Remote-access scam', 'MEDIUM'),
('give remote access', 'Remote-access scam', 'HIGH'),
('remote control your device', 'Remote-access scam', 'HIGH'),

-- 9. Advance Fee and Refund Scams
('pay upfront fee', 'Advance-fee scam', 'HIGH'),
('tax clearance certificate', 'Advance-fee scam', 'MEDIUM'),
('customs clearance fee', 'Advance-fee scam', 'HIGH'),
('release payment fee', 'Advance-fee scam', 'HIGH'),
('refund activation fee', 'Advance-fee scam', 'HIGH'),
('delivery charges pending', 'Advance-fee scam', 'MEDIUM'),
('processing charges required', 'Advance-fee scam', 'MEDIUM'),
('pay to receive money', 'Advance-fee scam', 'HIGH'),
('claim refund immediately', 'Refund scam', 'MEDIUM'),

-- 10. General Suspicious Phrases
('prince', 'Advance-fee scam', 'LOW'),
('unexpected inheritance', 'Advance-fee scam', 'MEDIUM'),
('secret investment scheme', 'Investment scam', 'HIGH'),
('free money transfer', 'Advance-fee scam', 'HIGH'),
('unclaimed funds', 'Advance-fee scam', 'MEDIUM'),
('suspicious payment request', 'Payment fraud', 'MEDIUM'),
('unauthorized transaction', 'Payment fraud', 'MEDIUM'),
('verify payment immediately', 'Payment fraud', 'MEDIUM'),
('bank account verification', 'Phishing', 'MEDIUM'),
('your account is at risk', 'Phishing', 'HIGH');