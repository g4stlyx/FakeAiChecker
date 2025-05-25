-- Initialize the FakeAiChecker database
USE FakeAiChecker;

-- Grant permissions to the application user
GRANT ALL PRIVILEGES ON FakeAiChecker.* TO 'fakeai_user'@'%';
FLUSH PRIVILEGES;

-- Create indexes for better performance
CREATE INDEX idx_scanresults_sessionid ON ScanResults(SessionId);
CREATE INDEX idx_scanresults_scandate ON ScanResults(ScanDate);
CREATE INDEX idx_secretfindings_scanresultid ON SecretFindings(ScanResultId);
CREATE INDEX idx_secretfindings_secrettype ON SecretFindings(SecretType);
CREATE INDEX idx_auditlogs_sessionid ON AuditLogs(SessionId);
CREATE INDEX idx_auditlogs_timestamp ON AuditLogs(Timestamp);
