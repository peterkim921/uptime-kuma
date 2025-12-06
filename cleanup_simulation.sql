
DELETE FROM notification WHERE name IN ('Mock Discord', 'Mock Slack');
DELETE FROM monitor_notification_rule_notification WHERE notification_id IN (SELECT id FROM notification WHERE name IN ('Mock Discord', 'Mock Slack'));
