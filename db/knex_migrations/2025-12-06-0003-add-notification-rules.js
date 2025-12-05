// Add column notification_rules to monitor table for time-based notification routing
exports.up = function (knex) {
    return knex.schema
        .alterTable("monitor", function (table) {
            table.text("notification_rules", "text").defaultTo(null);
        });
};

exports.down = function (knex) {
    return knex.schema.alterTable("monitor", function (table) {
        table.dropColumn("notification_rules");
    });
};

