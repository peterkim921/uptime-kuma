
const { R } = require("redbean-node");
const Database = require("./server/database");

async function main() {
    console.log("Starting simulation setup...");

    // Initialize Database
    // We need to mock args for Database.initDataDir if it uses them, but usually it defaults.
    // Let's check if we need to set up anything else.
    // Database.connect() usually handles the connection.

    try {
        await Database.connect();
        console.log("Connected to database.");

        const userID = 1; // Assuming the main user is ID 1

        // 1. Add Mock Discord Notification
        let discord = await R.findOne("notification", " name = ? ", ["Mock Discord"]);
        if (!discord) {
            discord = R.dispense("notification");
            discord.name = "Mock Discord";
            discord.type = "discord";
            discord.config = JSON.stringify({
                webhookUrl: "https://discord.com/api/webhooks/mock/12345",
                discordUsername: "Uptime Kuma",
                discordIcon: ""
            });
            discord.user_id = userID;
            await R.store(discord);
            console.log("✅ Added 'Mock Discord' notification.");
        } else {
            console.log("ℹ️ 'Mock Discord' already exists.");
        }

        // 2. Add Mock Slack Notification
        let slack = await R.findOne("notification", " name = ? ", ["Mock Slack"]);
        if (!slack) {
            slack = R.dispense("notification");
            slack.name = "Mock Slack";
            slack.type = "slack";
            slack.config = JSON.stringify({
                webhookUrl: "https://hooks.slack.com/services/mock/12345",
                channel: "#general",
                username: "Uptime Kuma"
            });
            slack.user_id = userID;
            await R.store(slack);
            console.log("✅ Added 'Mock Slack' notification.");
        } else {
            console.log("ℹ️ 'Mock Slack' already exists.");
        }

        // 3. Add Failing Monitor
        let monitor = await R.findOne("monitor", " name = ? ", ["Simulation Offline Site"]);
        if (!monitor) {
            monitor = R.dispense("monitor");
            monitor.name = "Simulation Offline Site";
            monitor.type = "http";
            monitor.url = "http://localhost:54321"; // Likely closed port
            monitor.interval = 10; // Check every 10 seconds
            monitor.user_id = userID;
            monitor.active = 1;
            await R.store(monitor);
            console.log("✅ Added 'Simulation Offline Site' monitor.");

            // 4. Add Notification Rule
            // Delay 30s, send to Discord
            let rule = R.dispense("monitor_notification_rule");
            rule.monitor_id = monitor.id;
            rule.delay = 30;
            rule.active = 1;
            await R.store(rule);

            let ruleNotif = R.dispense("monitor_notification_rule_notification");
            ruleNotif.monitor_notification_rule_id = rule.id;
            ruleNotif.notification_id = discord.id;
            await R.store(ruleNotif);
            console.log("✅ Added Notification Rule: Delay 30s -> Mock Discord.");
        } else {
            console.log("ℹ️ 'Simulation Offline Site' monitor already exists.");
        }

    } catch (e) {
        console.error("Error during setup:", e);
    } finally {
        await Database.close();
        console.log("Database connection closed.");
    }
}

main();
