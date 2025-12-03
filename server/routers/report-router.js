const express = require("express");
const router = express.Router();
const { R } = require("redbean-node");
const { checkLogin } = require("../util-server");
const dayjs = require("dayjs");

const fs = require("fs");
const path = require("path");
const jwt = require("jsonwebtoken");
const { UptimeKumaServer } = require("../uptime-kuma-server");

// Middleware to check login (JWT)
const checkAuth = (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader) {
            throw new Error("No authorization header");
        }

        const token = authHeader.split(" ")[1];
        if (!token) {
            throw new Error("No token provided");
        }

        const server = UptimeKumaServer.getInstance();
        const decoded = jwt.verify(token, server.jwtSecret);

        req.username = decoded.username;
        next();
    } catch (error) {
        res.status(401).json({ ok: false, msg: "Unauthorized: " + error.message });
    }
};

router.use(checkAuth);

/**
 * Get aggregated stats for monitors within a date range
 * Query Params:
 * - startDate: ISO string
 * - endDate: ISO string
 * - monitorIds: comma separated IDs (optional, default all)
 */
router.get("/stats", async (req, res) => {
    try {
        const { startDate, endDate, monitorIds } = req.query;

        if (!startDate || !endDate) {
            return res.status(400).json({ ok: false, msg: "Missing startDate or endDate" });
        }

        let monitorIdList = [];
        if (monitorIds) {
            monitorIdList = monitorIds.split(",").map(id => parseInt(id));
        } else {
            const monitors = await R.getAll("SELECT id FROM monitor WHERE active = 1");
            monitorIdList = monitors.map(m => m.id);
        }

        const stats = [];

        for (const monitorId of monitorIdList) {
            const monitor = await R.findOne("monitor", "id = ?", [monitorId]);
            if (!monitor) continue;

            // Aggregate heartbeats
            // status: 0 = DOWN, 1 = UP
            const result = await R.getRow(`
                SELECT 
                    COUNT(*) as total_pings,
                    SUM(CASE WHEN status = 0 THEN 1 ELSE 0 END) as downtime_count,
                    AVG(ping) as avg_ping
                FROM heartbeat 
                WHERE monitor_id = ? 
                AND time BETWEEN ? AND ?
            `, [monitorId, startDate, endDate]);

            const totalPings = result.total_pings || 0;
            const downtimeCount = result.downtime_count || 0;
            const avgPing = result.avg_ping || 0;

            let uptimePercent = 0;
            if (totalPings > 0) {
                uptimePercent = ((totalPings - downtimeCount) / totalPings) * 100;
            }

            stats.push({
                monitorId: monitor.id,
                name: monitor.name,
                uptimePercent: parseFloat(uptimePercent.toFixed(2)),
                downtimeCount: parseInt(downtimeCount),
                avgPing: parseFloat(avgPing.toFixed(2))
            });
        }

        res.json({ ok: true, stats });
    } catch (error) {
        console.error(error);
        res.status(500).json({ ok: false, msg: error.message });
    }
});

/**
 * Export stats as CSV
 */
router.get("/export/csv", async (req, res) => {
    try {
        // Reuse logic or call internal function (simplified for now by duplicating logic or extracting)
        // For brevity, I'll duplicate the aggregation logic or refactor later. 
        // Let's copy-paste for safety in this iteration.

        const { startDate, endDate, monitorIds } = req.query;

        // ... (Same aggregation logic as above) ...
        // To avoid code duplication in production, I would extract this to a service.
        // For this task, I will implement it inline.

        let monitorIdList = [];
        if (monitorIds) {
            monitorIdList = monitorIds.split(",").map(id => parseInt(id));
        } else {
            const monitors = await R.getAll("SELECT id FROM monitor WHERE active = 1");
            monitorIdList = monitors.map(m => m.id);
        }

        let csvContent = "Monitor Name,Uptime (%),Downtime Count,Avg Ping (ms)\n";

        for (const monitorId of monitorIdList) {
            const monitor = await R.findOne("monitor", "id = ?", [monitorId]);
            if (!monitor) continue;

            const result = await R.getRow(`
                SELECT 
                    COUNT(*) as total_pings,
                    SUM(CASE WHEN status = 0 THEN 1 ELSE 0 END) as downtime_count,
                    AVG(ping) as avg_ping
                FROM heartbeat 
                WHERE monitor_id = ? 
                AND time BETWEEN ? AND ?
            `, [monitorId, startDate, endDate]);

            const totalPings = result.total_pings || 0;
            const downtimeCount = result.downtime_count || 0;
            const avgPing = result.avg_ping || 0;

            let uptimePercent = 0;
            if (totalPings > 0) {
                uptimePercent = ((totalPings - downtimeCount) / totalPings) * 100;
            }

            csvContent += `"${monitor.name}",${uptimePercent.toFixed(2)},${downtimeCount},${parseFloat(avgPing.toFixed(2))}\n`;
        }

        res.header("Content-Type", "text/csv");
        res.attachment(`uptime_report_${dayjs().format("YYYY-MM-DD")}.csv`);
        res.send(csvContent);

    } catch (error) {
        console.error(error);
        res.status(500).send("Error generating CSV");
    }
});



module.exports = router;
