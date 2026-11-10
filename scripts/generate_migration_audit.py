from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS = ROOT / "supabase" / "migrations"
OUTPUT = ROOT / "scripts" / "migration_audit.sql"

TABLE_RE = re.compile(
    r"create\s+(?:unlogged\s+)?table\s+(?:if\s+not\s+exists\s+)?" r"(?:public\.)?[\"']?([a-zA-Z_][a-zA-Z0-9_]*)[\"']?",
    re.IGNORECASE,
)

FUNCTION_RE = re.compile(
    r"create\s+(?:or\s+replace\s+)?function\s+" r"(?:public\.)?[\"']?([a-zA-Z_][a-zA-Z0-9_]*)[\"']?\s*\(",
    re.IGNORECASE,
)

tables = {}
functions = {}

for path in sorted(MIGRATIONS.glob("*.sql")):
    sql = path.read_text(encoding="utf-8", errors="replace")
    sql = re.sub(r"--[^\n]*", "", sql)

    for match in TABLE_RE.finditer(sql):
        name = match.group(1).lower()
        tables.setdefault(name, path.name)

    for match in FUNCTION_RE.finditer(sql):
        name = match.group(1).lower()
        functions.setdefault(name, path.name)

rows = []
for name, source in sorted(tables.items()):
    rows.append(f"    ('table', '{name}', '{source}')")

for name, source in sorted(functions.items()):
    rows.append(f"    ('function', '{name}', '{source}')")

values = ",\n".join(rows)

sql = f"""-- Auto-generated migration audit.
-- Run this in Supabase SQL Editor.
-- Any row with present = false needs the migration in source applied.

with expected(kind, object_name, source) as (
    values
{values}
)
select
    e.kind,
    e.object_name,
    e.source,
    case e.kind
        when 'table' then
            exists (
                select 1
                from pg_class c
                join pg_namespace n on n.oid = c.relnamespace
                where n.nspname = 'public'
                  and c.relname = e.object_name
                  and c.relkind in ('r', 'p')
            )
        else
            exists (
                select 1
                from pg_proc p
                join pg_namespace n on n.oid = p.pronamespace
                where n.nspname = 'public'
                  and p.proname = e.object_name
            )
    end as present
from expected e
order by
    present asc,
    e.source,
    e.kind,
    e.object_name;
"""

OUTPUT.write_text(sql, encoding="utf-8")
print(f"Created {OUTPUT}")
print(f"Tables detected: {len(tables)}")
print(f"Functions detected: {len(functions)}")
