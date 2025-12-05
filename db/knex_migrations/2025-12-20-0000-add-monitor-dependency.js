exports.up = function (knex) {
    return knex.schema.hasTable("monitor_dependency").then(function(exists) {
        if (exists) {
            // 如果表已存在（可能是之前失败的迁移），先删除它
            return knex.schema.dropTable("monitor_dependency").then(function() {
                return createTable(knex);
            });
        } else {
            return createTable(knex);
        }
    });
};

function createTable(knex) {
    return knex.schema.createTable("monitor_dependency", function (table) {
        table.increments("id");
        table.integer("monitor_id").unsigned().notNullable()
            .references("id").inTable("monitor")
            .onDelete("CASCADE")
            .onUpdate("CASCADE");
        table.integer("depends_on_monitor_id").unsigned().notNullable()
            .references("id").inTable("monitor")
            .onDelete("CASCADE")
            .onUpdate("CASCADE");
        table.string("relation_type", 20).defaultTo("hard");
        
        // 防止重复依赖关系
        table.unique([ "monitor_id", "depends_on_monitor_id" ], "monitor_dependency_unique");
        
        // 添加索引以提高查询性能（使用表名前缀避免冲突）
        table.index("monitor_id", "monitor_dependency_monitor_id_idx");
        table.index("depends_on_monitor_id", "monitor_dependency_depends_on_idx");
    });
}

exports.down = function (knex) {
    return knex.schema.dropTable("monitor_dependency");
};

