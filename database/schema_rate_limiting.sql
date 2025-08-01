-- Rate limiting schema for share access attempts
-- Phase 5E: EntityID-based rate limiting with exponential backoff

-- Note: share_access_attempts table is already defined in schema_extensions.sql
-- This file only contains the indexes and views for rate limiting

-- Indexes for efficient rate limiting queries (may already exist from schema_extensions.sql)
CREATE INDEX IF NOT EXISTS idx_share_access_attempts_share_entity ON share_access_attempts(share_id, entity_id);
CREATE INDEX IF NOT EXISTS idx_share_access_attempts_next_allowed ON share_access_attempts(next_allowed_attempt);
CREATE INDEX IF NOT EXISTS idx_share_access_attempts_created_at ON share_access_attempts(created_at);

-- Update trigger to maintain updated_at timestamp
CREATE TRIGGER IF NOT EXISTS update_share_access_attempts_updated_at
    AFTER UPDATE ON share_access_attempts
    FOR EACH ROW
BEGIN
    UPDATE share_access_attempts 
    SET updated_at = CURRENT_TIMESTAMP 
    WHERE id = NEW.id;
END;

-- Cleanup old rate limiting entries (older than 30 days)
-- This should be run periodically by a maintenance script
-- DELETE FROM share_access_attempts WHERE created_at < datetime('now', '-30 days');

-- View for monitoring rate limiting activity
CREATE VIEW IF NOT EXISTS share_rate_limit_stats AS
SELECT 
    COUNT(*) as total_entries,
    COUNT(CASE WHEN failed_count > 0 THEN 1 END) as entries_with_failures,
    COUNT(CASE WHEN next_allowed_attempt > CURRENT_TIMESTAMP THEN 1 END) as currently_blocked,
    AVG(failed_count) as avg_failure_count,
    MAX(failed_count) as max_failure_count,
    COUNT(CASE WHEN failed_count >= 10 THEN 1 END) as entries_at_max_penalty
FROM share_access_attempts;

-- View for monitoring share access patterns
CREATE VIEW IF NOT EXISTS share_access_monitoring AS
SELECT 
    share_id,
    COUNT(DISTINCT entity_id) as unique_entities,
    COUNT(*) as total_attempts,
    SUM(failed_count) as total_failures,
    COUNT(CASE WHEN next_allowed_attempt > CURRENT_TIMESTAMP THEN 1 END) as currently_blocked_entities,
    MAX(failed_count) as max_failures_by_entity,
    MIN(created_at) as first_attempt,
    MAX(COALESCE(last_failed_attempt, created_at)) as last_activity
FROM share_access_attempts
GROUP BY share_id
ORDER BY total_failures DESC, total_attempts DESC;
