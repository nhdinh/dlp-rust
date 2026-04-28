#!/usr/bin/env python3
import re

content = open('dlp-server/src/admin_api.rs', encoding='utf-8').read()

# 1. Remove Database import
content = re.sub(r'^use crate::db::Database;\s*$\n?', '', content, flags=re.MULTILINE)

# 2. Bulk replacements
content = content.replace('Arc::clone(&state.db)', 'Arc::clone(&state.pool)')
content = content.replace('db.conn().lock()', 'pool.get().map_err(AppError::from)?')

# 3. Update spawn_admin_app()
old_spawn = '''fn spawn_admin_app() -> axum::Router {
        crate::admin_auth::set_jwt_secret(TEST_JWT_SECRET.to_string());
        let db = Arc::new(crate::db::Database::open(":memory:").expect("open db"));
        let siem = crate::siem_connector::SiemConnector::new(Arc::clone(&db));
        let alert = crate::alert_router::AlertRouter::new(Arc::clone(&db));
        let state = Arc::new(AppState {
            db,
            siem,
            alert,
            ad: None,
        });
        admin_router(state)
    }'''

new_spawn = '''fn spawn_admin_app() -> axum::Router {
        crate::admin_auth::set_jwt_secret(TEST_JWT_SECRET.to_string());
        let tmp = tempfile::NamedTempFile::new().expect("create temp db");
        let pool = Arc::new(crate::db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));
        let siem = crate::siem_connector::SiemConnector::new(Arc::clone(&pool));
        let alert = crate::alert_router::AlertRouter::new(Arc::clone(&pool));
        let state = Arc::new(AppState {
            pool,
            siem,
            alert,
            ad: None,
        });
        admin_router(state)
    }'''

content = content.replace(old_spawn, new_spawn)

# 4. Update seed_agent helper
old_seed = '''fn seed_agent(db: &crate::db::Database, agent_id: &str) {
        let conn = db.conn().lock();'''

new_seed = '''fn seed_agent(pool: &crate::db::Pool, agent_id: &str) {
        let conn = pool.get().expect("acquire connection");'''

content = content.replace(old_seed, new_seed)

# 5. Inline fixtures: the full pattern with Database::open
# Pattern: let db = Arc::new(crate::db::Database::open(":memory:").expect("open db"));
# followed by seed_agent(&db, ...) or siem/alert/Arc::clone(&db)

# Replace all remaining let db = Arc::new(crate::db::Database::open(":memory:").expect("open db"));
content = re.sub(
    r'let db = Arc::new\(crate::db::Database::open\(":memory:"\)\.expect\("open db"\)\);',
    'let tmp = tempfile::NamedTempFile::new().expect("create temp db");\n        let pool = Arc::new(crate::db::new_pool(tmp.path().to_str().unwrap()).expect("build pool"));',
    content
)

# 6. Fix seed_agent(&db, ...) → seed_agent(&pool, ...)
content = content.replace('seed_agent(&db,', 'seed_agent(&pool,')

# 7. Fix remaining Arc::clone(&db) → Arc::clone(&pool)
content = re.sub(r'SiemConnector::new\(Arc::clone\(&db\)\)', 'SiemConnector::new(Arc::clone(&pool))', content)
content = re.sub(r'AlertRouter::new\(Arc::clone\(&db\)\)', 'AlertRouter::new(Arc::clone(&pool))', content)
content = re.sub(r'Arc::clone\(&db\)', 'Arc::clone(&pool)', content)

# 8. Fix AppState { db, siem, ... } → { pool, siem, ... }
# Multi-line pattern
content = re.sub(
    r'let state = Arc::new\(AppState \{\n'
    r'            db,\n'
    r'            siem,\n'
    r'            alert,\n'
    r'            ad: None,\n'
    r'        \}\);',
    '''let state = Arc::new(AppState {
            pool,
            siem,
            alert,
            ad: None,
        });''',
    content
)
# Single-line pattern
content = re.sub(
    r'let state = Arc::new\(AppState \{ db, siem, alert, ad: None \}\);',
    'let state = Arc::new(AppState { pool, siem, alert, ad: None });',
    content
)

# 9. Fix test_db_insert_select_roundtrip_via_spawn_blocking
old_roundtrip_vars = '''        let db = Arc::new(crate::db::Database::open(":memory:").expect("open db"));
        let db2 = Arc::clone(&db);'''
new_roundtrip_vars = '''        let pool = Arc::new(crate::db::new_pool(":memory:").expect("open db"));
        let pool2 = Arc::clone(&pool);'''
content = content.replace(old_roundtrip_vars, new_roundtrip_vars)

# Fix the closures in that test: db.conn().lock() → pool.get().expect()
# Already handled by bulk replace but need correct variable names

# 10. Fix test_router_post_then_direct_db_read
content = content.replace('let db_read = Arc::clone(&db);', 'let pool_read = Arc::clone(&pool);')
content = content.replace('let conn = db_read.conn().lock();', 'let conn = pool_read.get().expect("acquire connection");')

# 11. Fix Database::open in doc comments
content = content.replace('seeded during `Database::open`.', 'seeded during table init.')

# 12. Fix remaining: app oneshot closures with db.conn().lock()
# After all replacements, any remaining db.conn().lock() should be pool.get().map_err(...)
# But the variable might still be called 'db' in some places - fix those

# Check for remaining issues
lines = content.split('\n')
issues = []
for i, line in enumerate(lines, 1):
    if 'state.db' in line:
        issues.append(f'  line {i}: {line}')
    if re.search(r'db\.conn\(\)', line):
        issues.append(f'  line {i}: {line}')
    if 'Database::open' in line and 'crate::db::Database' in line:
        issues.append(f'  line {i}: {line}')

for issue in issues:
    print(issue)
print(f'Issue count: {len(issues)}')

with open('dlp-server/src/admin_api.rs', 'w', encoding='utf-8') as f:
    f.write(content)
print('done')
