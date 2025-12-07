
exports.up = function (knex) {
    return knex.schema
        .createTable("monitor_dependency", function (table) {
            table.increments("id");
            table.integer("monitor_id").unsigned().notNullable().references("id").inTable("monitor").onDelete("CASCADE").onUpdate("CASCADE");
            table.integer("depends_on_monitor_id").unsigned().notNullable().references("id").inTable("monitor").onDelete("CASCADE").onUpdate("CASCADE");
            table.string("relation_type").notNullable().defaultTo("hard");
            table.unique(["monitor_id", "depends_on_monitor_id"]);
        });
};

exports.down = function (knex) {
    return knex.schema
        .dropTable("monitor_dependency");
};
