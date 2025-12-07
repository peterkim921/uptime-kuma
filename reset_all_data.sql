-- 清空所有数据但保留用户账户的脚本
-- 这个脚本会删除所有监控、心跳、统计等数据，但保留用户表，让你可以继续登录

-- 删除统计表数据
DELETE FROM stat_minutely;
DELETE FROM stat_hourly;
DELETE FROM stat_daily;

-- 删除心跳记录
DELETE FROM heartbeat;

-- 删除监控通知规则关联
DELETE FROM monitor_notification_rule_notification;

-- 删除监控通知规则
DELETE FROM monitor_notification_rule;

-- 删除监控 TLS 信息
DELETE FROM monitor_tls_info;

-- 删除监控组关联
DELETE FROM monitor_group;

-- 删除维护记录
DELETE FROM maintenance;

-- 删除监控标签关联
DELETE FROM monitor_tag;

-- 删除标签
DELETE FROM tag;

-- 删除通知记录
DELETE FROM notification;

-- 删除代理设置
DELETE FROM proxy;

-- 删除 Docker 主机
DELETE FROM docker_host;

-- 删除状态页面
DELETE FROM status_page;

-- 删除组
DELETE FROM group;

-- 删除监控（最后删除，因为其他表可能引用它）
DELETE FROM monitor;

-- 如果使用 SQLite，优化数据库
-- PRAGMA optimize;

-- 注意：用户表 (user) 不会被删除，你可以继续使用现有账户登录

