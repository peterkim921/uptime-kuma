const { R } = require("redbean-node");
const Database = require("./server/database");
const args = require("args-parser")(process.argv);

/**
 * 清空所有监控数据、心跳记录和统计，但保留用户账户
 * 使用方式: node reset_all_data.js
 */
const main = async () => {
    console.log("正在连接数据库...");
    Database.initDataDir(args);
    await Database.connect(false, false, true);

    try {
        console.log("开始清空数据...");
        
        // 删除统计表数据
        console.log("  删除统计表数据...");
        await R.exec("DELETE FROM stat_minutely");
        await R.exec("DELETE FROM stat_hourly");
        await R.exec("DELETE FROM stat_daily");

        // 删除心跳记录
        console.log("  删除心跳记录...");
        await R.exec("DELETE FROM heartbeat");

        // 删除监控通知规则关联
        console.log("  删除监控通知规则关联...");
        await R.exec("DELETE FROM monitor_notification_rule_notification");

        // 删除监控通知规则
        console.log("  删除监控通知规则...");
        await R.exec("DELETE FROM monitor_notification_rule");

        // 删除监控 TLS 信息
        console.log("  删除监控 TLS 信息...");
        await R.exec("DELETE FROM monitor_tls_info");

        // 删除监控组关联
        console.log("  删除监控组关联...");
        await R.exec("DELETE FROM monitor_group");

        // 删除维护记录
        console.log("  删除维护记录...");
        await R.exec("DELETE FROM maintenance");

        // 删除监控标签关联
        console.log("  删除监控标签关联...");
        await R.exec("DELETE FROM monitor_tag");

        // 删除标签
        console.log("  删除标签...");
        await R.exec("DELETE FROM tag");

        // 删除通知记录
        console.log("  删除通知记录...");
        await R.exec("DELETE FROM notification");

        // 删除代理设置
        console.log("  删除代理设置...");
        await R.exec("DELETE FROM proxy");

        // 删除 Docker 主机
        console.log("  删除 Docker 主机...");
        await R.exec("DELETE FROM docker_host");

        // 删除状态页面
        console.log("  删除状态页面...");
        await R.exec("DELETE FROM status_page");

        // 删除组
        console.log("  删除组...");
        await R.exec("DELETE FROM `group`");

        // 删除监控（最后删除，因为其他表可能引用它）
        console.log("  删除监控...");
        await R.exec("DELETE FROM monitor");

        // 如果使用 SQLite，优化数据库
        if (Database.dbConfig.type === "sqlite") {
            console.log("  优化 SQLite 数据库...");
            await R.exec("PRAGMA optimize;");
        }

        console.log("\n✅ 数据清空完成！");
        console.log("📝 注意：用户账户已保留，你可以继续使用现有账户登录。");
        console.log("   所有监控、心跳记录、统计数据已被清空。");

    } catch (error) {
        console.error("❌ 清空数据时发生错误:", error.message);
        process.exit(1);
    } finally {
        await Database.close();
    }
};

main().catch((error) => {
    console.error("❌ 执行失败:", error);
    process.exit(1);
});

