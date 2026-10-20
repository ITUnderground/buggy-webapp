-- ===========================================================================
--  VulnLab database seed  —  FOR LOCAL / LAB USE ONLY
--  Everything here is FAKE. The card numbers are the standard non-functional
--  test PANs (4111..., 5500...) that never belong to a real account. The whole
--  point is to give a learner something recognizable to "find" after they get
--  in using default credentials.
-- ===========================================================================
USE appdb;

-- Fake customer PII — the kind of table that should never sit behind a
-- default password on an open port.
CREATE TABLE customers (
    id          INT PRIMARY KEY AUTO_INCREMENT,
    name        VARCHAR(100),
    email       VARCHAR(100),
    credit_card VARCHAR(25),
    notes       VARCHAR(255)
);

INSERT INTO customers (name, email, credit_card, notes) VALUES
    ('Alice Example', 'alice@example.test', '4111-1111-1111-1111', 'fake test card'),
    ('Bob Sample',    'bob@example.test',   '5500-0000-0000-0004', 'fake test card'),
    ('Carol Demo',    'carol@example.test', '3400-0000-0000-0009', 'fake test card');

-- Fake application secrets — the real prize.
CREATE TABLE app_secrets (
    k VARCHAR(50) PRIMARY KEY,
    v VARCHAR(255)
);

INSERT INTO app_secrets (k, v) VALUES
    ('jwt_signing_secret', 'super-secret-jwt-signing-key-do-not-share'),
    ('smtp_password',      'P@ssw0rd-mailer-2023'),
    ('flag',               'flag{exposed_db_default_creds}');
