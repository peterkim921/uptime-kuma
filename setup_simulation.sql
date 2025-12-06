
-- Add Mock Discord
INSERT INTO notification (name, config, user_id, is_default, active)
SELECT 'Mock Discord', '{"type":"discord","webhookUrl":"https://discord.com/api/webhooks/mock/12345","discordUsername":"Uptime Kuma","discordIcon":""}', 1, 0, 1
WHERE NOT EXISTS (SELECT 1 FROM notification WHERE name = 'Mock Discord');

-- Add Mock Slack
INSERT INTO notification (name, config, user_id, is_default, active)
SELECT 'Mock Slack', '{"type":"slack","webhookUrl":"https://hooks.slack.com/services/mock/12345","channel":"#general","username":"Uptime Kuma"}', 1, 0, 1
WHERE NOT EXISTS (SELECT 1 FROM notification WHERE name = 'Mock Slack');

-- Add Failing Monitor
INSERT INTO monitor (name, type, url, interval, user_id, active, accepted_statuscodes_json)
SELECT 'Simulation Offline Site', 'http', 'http://localhost:54321', 10, 1, 1, '["200-299"]'
WHERE NOT EXISTS (SELECT 1 FROM monitor WHERE name = 'Simulation Offline Site');

-- Add Rule (Delay 30s)
INSERT INTO monitor_notification_rule (monitor_id, delay, active)
SELECT id, 30, 1 FROM monitor WHERE name = 'Simulation Offline Site'
AND NOT EXISTS (SELECT 1 FROM monitor_notification_rule WHERE monitor_id = (SELECT id FROM monitor WHERE name = 'Simulation Offline Site') AND delay = 30);

-- Link Rule to Discord
INSERT INTO monitor_notification_rule_notification (monitor_notification_rule_id, notification_id)
SELECT r.id, n.id
FROM monitor_notification_rule r
JOIN monitor m ON r.monitor_id = m.id
JOIN notification n ON n.name = 'Mock Discord'
WHERE m.name = 'Simulation Offline Site'
AND NOT EXISTS (SELECT 1 FROM monitor_notification_rule_notification WHERE monitor_notification_rule_id = r.id AND notification_id = n.id);
