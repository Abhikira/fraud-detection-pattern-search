CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'USER' CHECK (role IN ('ADMIN', 'USER')),
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS transactions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NULL REFERENCES users(id) ON DELETE CASCADE,
  account_ref TEXT NOT NULL,
  description TEXT NOT NULL,
  amount TEXT NOT NULL DEFAULT '0',
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_transactions_user_created
  ON transactions (user_id, created_at);

CREATE TABLE IF NOT EXISTS suspicious_patterns (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  pattern_text TEXT NOT NULL UNIQUE,
  category TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH'))
);

CREATE TABLE IF NOT EXISTS detection_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  transaction_id INTEGER NOT NULL REFERENCES transactions(id) ON DELETE CASCADE,
  pattern_id INTEGER NOT NULL REFERENCES suspicious_patterns(id) ON DELETE CASCADE,
  algorithm TEXT NOT NULL,
  match_count INTEGER NOT NULL,
  positions TEXT NOT NULL,
  risk_level TEXT NOT NULL CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH')),
  detected_at TEXT NOT NULL
);

INSERT OR IGNORE INTO suspicious_patterns (pattern_text, category, severity) VALUES
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
