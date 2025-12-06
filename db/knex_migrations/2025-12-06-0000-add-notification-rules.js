
exports.up = function (knex) {
    return knex.schema
        .createTable("monitor_notification_rule", function (table) {
            table.increments("id");
            table.integer("monitor_id").unsigned().notNullable().references("id").inTable("monitor").onDelete("CASCADE").onUpdate("CASCADE");
            table.integer("delay").notNullable().defaultTo(0);
            table.boolean("active").notNullable().defaultTo(1);
        })
        .createTable("monitor_notification_rule_notification", function (table) {
            table.increments("id");
            table.integer("monitor_notification_rule_id").unsigned().notNullable().references("id").inTable("monitor_notification_rule").onDelete("CASCADE").onUpdate("CASCADE");
            table.integer("notification_id").unsigned().notNullable().references("id").inTable("notification").onDelete("CASCADE").onUpdate("CASCADE");
        });
};

exports.down = function (knex) {
    return knex.schema
        .dropTable("monitor_notification_rule_notification")
        .dropTable("monitor_notification_rule");
};
