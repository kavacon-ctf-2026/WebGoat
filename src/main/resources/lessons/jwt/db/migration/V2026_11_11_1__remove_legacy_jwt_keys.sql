-- KID validation now uses a trusted in-memory key; the legacy table stored weak keys in plaintext.
DROP TABLE IF EXISTS jwt_keys;
