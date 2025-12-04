const { MonitorType } = require("./monitor-type");
const { UP } = require("../../src/util");
const dayjs = require("dayjs");
const { dnsResolve } = require("../util-server");
const { R } = require("redbean-node");
const { ConditionVariable } = require("../monitor-conditions/variables");
const { defaultStringOperators } = require("../monitor-conditions/operators");
const { ConditionExpressionGroup } = require("../monitor-conditions/expression");
const { evaluateExpressionGroup } = require("../monitor-conditions/evaluator");
const validator = require("validator");

class DnsMonitorType extends MonitorType {
    name = "dns";

    supportsConditions = true;

    conditionVariables = [
        new ConditionVariable("record", defaultStringOperators ),
    ];

    /**
     * @inheritdoc
     */
    async check(monitor, heartbeat, _server) {
        // Validate that hostname is a valid FQDN (Fully Qualified Domain Name)
        // allow_wildcard: true allows hostnames like *.example.com
        if (!validator.isFQDN(monitor.hostname, { allow_wildcard: true })) {
            throw new Error("Hostname must be a valid domain name (e.g., example.com or *.example.com). IP addresses are not allowed.");
        }

        // Handle wildcard hostname (e.g., *.example.com)
        let actualHostname = monitor.hostname;
        if (monitor.hostname && monitor.hostname.startsWith("*")) {
            // Get or initialize wildcard counter
            if (!monitor.wildcardCounter) {
                monitor.wildcardCounter = 1;
            }
            // Replace * with random<counter>
            actualHostname = monitor.hostname.replace(/^\*/, `random${monitor.wildcardCounter}`);

            // Log the wildcard replacement for debugging
            console.log(`[DNS Monitor #${monitor.id}] Wildcard hostname: ${monitor.hostname} -> ${actualHostname} (test #${monitor.wildcardCounter})`);

            // Increment counter for next check
            monitor.wildcardCounter++;
        }

        let startTime = dayjs().valueOf();
        let dnsMessage = "";

        let dnsRes = await dnsResolve(actualHostname, monitor.dns_resolve_server, monitor.port, monitor.dns_resolve_type);
        heartbeat.ping = dayjs().valueOf() - startTime;

        // If wildcard was used, include it in the message
        if (actualHostname !== monitor.hostname) {
            dnsMessage = `[${actualHostname}] `;
        }

        const conditions = ConditionExpressionGroup.fromMonitor(monitor);
        let conditionsResult = true;
        const handleConditions = (data) => conditions ? evaluateExpressionGroup(conditions, data) : true;

        switch (monitor.dns_resolve_type) {
            case "A":
            case "AAAA":
            case "PTR":
                dnsMessage += `Records: ${dnsRes.join(" | ")}`;
                conditionsResult = dnsRes.some(record => handleConditions({ record }));
                break;

            case "TXT":
                dnsMessage += `Records: ${dnsRes.join(" | ")}`;
                conditionsResult = dnsRes.flat().some(record => handleConditions({ record }));
                break;

            case "CNAME":
                dnsMessage += dnsRes[0];
                conditionsResult = handleConditions({ record: dnsRes[0] });
                break;

            case "CAA":
                dnsMessage += dnsRes[0].issue;
                conditionsResult = handleConditions({ record: dnsRes[0].issue });
                break;

            case "MX":
                dnsMessage = dnsRes.map(record => `Hostname: ${record.exchange} - Priority: ${record.priority}`).join(" | ");
                conditionsResult = dnsRes.some(record => handleConditions({ record: record.exchange }));
                break;

            case "NS":
                dnsMessage = `Servers: ${dnsRes.join(" | ")}`;
                conditionsResult = dnsRes.some(record => handleConditions({ record }));
                break;

            case "SOA":
                dnsMessage = `NS-Name: ${dnsRes.nsname} | Hostmaster: ${dnsRes.hostmaster} | Serial: ${dnsRes.serial} | Refresh: ${dnsRes.refresh} | Retry: ${dnsRes.retry} | Expire: ${dnsRes.expire} | MinTTL: ${dnsRes.minttl}`;
                conditionsResult = handleConditions({ record: dnsRes.nsname });
                break;

            case "SRV":
                dnsMessage = dnsRes.map(record => `Name: ${record.name} | Port: ${record.port} | Priority: ${record.priority} | Weight: ${record.weight}`).join(" | ");
                conditionsResult = dnsRes.some(record => handleConditions({ record: record.name }));
                break;
        }

        if (monitor.dns_last_result !== dnsMessage && dnsMessage !== undefined) {
            await R.exec("UPDATE `monitor` SET dns_last_result = ? WHERE id = ? ", [ dnsMessage, monitor.id ]);
        }

        if (!conditionsResult) {
            throw new Error(dnsMessage);
        }

        heartbeat.msg = dnsMessage;
        heartbeat.status = UP;
    }
}

module.exports = {
    DnsMonitorType,
};
