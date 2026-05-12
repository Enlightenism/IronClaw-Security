import importlib

mod_a = importlib.import_module('app.services.incident_store')
mod_b = importlib.import_module('app.services.incidentstore')

cls_a  = getattr(mod_a, 'IncidentStoreInMemory', None)
cls_b  = getattr(mod_b, 'IncidentStore', None)
shim_a = getattr(mod_a, 'IncidentStore', None)
shim_b = getattr(mod_b, 'IncidentStore', None)

rec_a      = getattr(mod_a, 'IncidentRecordInMemory', None)
rec_b      = getattr(mod_b, 'IncidentRecord', None)
rec_shim_a = getattr(mod_a, 'IncidentRecord', None)
rec_shim_b = getattr(mod_b, 'IncidentRecord', None)

get_a    = getattr(mod_a, 'get_incident_store', None)
get_b    = getattr(mod_b, 'get_incident_store', None)
build_a  = getattr(mod_a, 'build_incident_store', None)
build_b  = getattr(mod_b, 'build_incident_store', None)
create_a = getattr(mod_a, 'create_incident_store', None)
create_b = getattr(mod_b, 'create_incident_store', None)
reset_a  = getattr(mod_a, 'reset_incident_store', None)
reset_b  = getattr(mod_b, 'reset_incident_store', None)
list_a   = getattr(mod_a, 'list_incidents', None)
list_b   = getattr(mod_b, 'list_incidents', None)

sing_a = getattr(mod_a, '_INCIDENT_STORE_MEMORY', None)
sing_b = getattr(mod_b, '_SINGLETON_STORE', None)

inst_a = get_a() if callable(get_a) else None
inst_b = get_b() if callable(get_b) else None

collisions = []
missing    = []
warnings   = []

def check(label, a, b, expect_same=False):
    if a is None:
        missing.append('MISSING  ' + label + ' in incident_store')
    if b is None:
        missing.append('MISSING  ' + label + ' in incidentstore')
    if a is not None and b is not None:
        same = a is b
        if expect_same and not same:
            warnings.append('WARN     ' + label + ' expected same object but differs')
        if not expect_same and same:
            collisions.append('COLLISION ' + label)
        status = 'SAME' if same else 'ISOLATED'
        print('  ' + status.ljust(10) + ' ' + label)
        print('             incident_store id : ' + str(id(a)))
        print('             incidentstore  id : ' + str(id(b)))

print()
print('=== PRIMARY CLASS IDENTITIES ===')
check('IncidentStoreInMemory / IncidentStore', cls_a, cls_b)

print()
print('=== BACK-COMPAT SHIM: IncidentStore ===')
print('  incident_store.IncidentStore -> IncidentStoreInMemory : ' + str(shim_a is cls_a))
print('  incidentstore.IncidentStore  -> IncidentStore         : ' + str(shim_b is cls_b))
if shim_a is shim_b:
    collisions.append('COLLISION IncidentStore shim cross-contamination')
    print('  COLLISION shims point to same object')
else:
    print('  ISOLATED  shims are independent')

print()
print('=== RECORD CLASS IDENTITIES ===')
check('IncidentRecordInMemory / IncidentRecord', rec_a, rec_b)
print('  incident_store.IncidentRecord -> IncidentRecordInMemory : ' + str(rec_shim_a is rec_a))
print('  incidentstore.IncidentRecord  -> IncidentRecord         : ' + str(rec_shim_b is rec_b))
if rec_shim_a is rec_shim_b:
    collisions.append('COLLISION IncidentRecord shim cross-contamination')

print()
print('=== FACTORY FUNCTIONS ===')
check('get_incident_store',    get_a,    get_b)
check('build_incident_store',  build_a,  build_b)
check('create_incident_store', create_a, create_b)
check('reset_incident_store',  reset_a,  reset_b)
check('list_incidents',        list_a,   list_b)

if build_a is None or id(build_a) == id(None):
    missing.append('MISSING  build_incident_store resolves to None in incident_store')
if create_a is None or id(create_a) == id(None):
    missing.append('MISSING  create_incident_store resolves to None in incident_store')

print()
print('=== SINGLETON ISOLATION ===')
print('  _INCIDENT_STORE_MEMORY present in incident_store : ' + str(sing_a is not None))
print('  _SINGLETON_STORE present in incidentstore        : ' + str(sing_b is not None))
print('  _SINGLETON_STORE leaked into incident_store?     : ' + str(hasattr(mod_a, '_SINGLETON_STORE')))
print('  _INCIDENT_STORE_MEMORY leaked into incidentstore?: ' + str(hasattr(mod_b, '_INCIDENT_STORE_MEMORY')))
if sing_a is not None and sing_a is sing_b:
    collisions.append('COLLISION singletons are same object')
    print('  COLLISION singletons are same object')
else:
    print('  ISOLATED  singleton ids: ' + str(id(sing_a)) + ' vs ' + str(id(sing_b)))
if hasattr(mod_a, '_SINGLETON_STORE'):
    collisions.append('COLLISION _SINGLETON_STORE leaked into incident_store')
if hasattr(mod_b, '_INCIDENT_STORE_MEMORY'):
    collisions.append('COLLISION _INCIDENT_STORE_MEMORY leaked into incidentstore')
if sing_a is not None and not sing_a.is_ready():
    warnings.append('WARN _INCIDENT_STORE_MEMORY.is_ready() returned False')
if sing_b is not None and not sing_b.is_ready():
    warnings.append('WARN _SINGLETON_STORE.is_ready() returned False')

print()
print('=== INSTANCE TYPE ASSERTION ===')
print('  incident_store get() -> IncidentStoreInMemory : ' + str(isinstance(inst_a, cls_a) if inst_a and cls_a else 'SKIP'))
print('  incidentstore  get() -> IncidentStore         : ' + str(isinstance(inst_b, cls_b) if inst_b and cls_b else 'SKIP'))
print('  Instances same object?                        : ' + str(inst_a is inst_b))
if inst_a is inst_b:
    collisions.append('COLLISION get_incident_store() returns same instance across modules')

print()
print('=== MODULE FILE ISOLATION ===')
print('  mod_a __file__ : ' + str(mod_a.__file__))
print('  mod_b __file__ : ' + str(mod_b.__file__))
if mod_a.__file__ == mod_b.__file__:
    collisions.append('COLLISION both modules resolve to same file')
    print('  COLLISION same file')
else:
    print('  ISOLATED  different files')

print()
print('=== MODULE __module__ ATTRIBUTES ===')
for name, obj in [('cls_a', cls_a), ('cls_b', cls_b), ('rec_a', rec_a), ('rec_b', rec_b)]:
    mod_attr = getattr(obj, '__module__', None) if obj else None
    print('  ' + name + '.__module__ : ' + str(mod_attr))

print()
print('=== DUCK-TYPE INTERFACE PARITY ===')
required = [
    'list_incidents', 'get_incident', 'create_incident',
    'update_incident_status', 'update_incident',
    'resolve_incident', 'close_incident', 'assign_incident',
    'summarize', 'reset', 'is_ready', 'healthcheck', 'as_dict',
    'seed_defaults',
]
for method in required:
    has_a = callable(getattr(cls_a, method, None)) if cls_a else False
    has_b = callable(getattr(cls_b, method, None)) if cls_b else False
    flag = 'OK' if has_a and has_b else ('A-ONLY' if has_a else ('B-ONLY' if has_b else 'MISSING-BOTH'))
    if flag != 'OK':
        warnings.append('INTERFACE ' + method + ' : ' + flag)
    print('  ' + flag.ljust(12) + ' ' + method)

print()
print('=== RECORD FIELD PARITY ===')
fields_a = {f.name for f in rec_a.__dataclass_fields__.values()} if rec_a and hasattr(rec_a, '__dataclass_fields__') else set()
fields_b = {f.name for f in rec_b.__dataclass_fields__.values()} if rec_b and hasattr(rec_b, '__dataclass_fields__') else set()
only_a = fields_a - fields_b
only_b = fields_b - fields_a
shared = fields_a & fields_b
print('  Shared fields  (' + str(len(shared)) + ') : ' + str(sorted(shared)))
if only_a:
    warnings.append('WARN record field only in incident_store: ' + str(sorted(only_a)))
    print('  Only in A      (' + str(len(only_a)) + ') : ' + str(sorted(only_a)))
if only_b:
    warnings.append('WARN record field only in incidentstore : ' + str(sorted(only_b)))
    print('  Only in B      (' + str(len(only_b)) + ') : ' + str(sorted(only_b)))

print()
print('=== LIVE SMOKE TEST ===')
try:
    r_a = inst_a.create_incident(title='smoke-a', summary='test', severity='low', source='system')
    print('  incident_store create_incident : OK  id=' + r_a.incident_id)
except Exception as exc:
    warnings.append('WARN incident_store create_incident raised: ' + str(exc))
    print('  incident_store create_incident : FAIL ' + str(exc))
try:
    fetched_a = inst_a.get_incident(r_a.incident_id)
    print('  incident_store get_incident    : ' + ('OK' if fetched_a else 'NOT FOUND'))
except Exception as exc:
    print('  incident_store get_incident    : FAIL ' + str(exc))
try:
    r_b = inst_b.create_incident(title='smoke-b', summary='test', severity='low', source='system')
    print('  incidentstore  create_incident : OK  id=' + r_b.incidentid)
except Exception as exc:
    warnings.append('WARN incidentstore create_incident raised: ' + str(exc))
    print('  incidentstore  create_incident : FAIL ' + str(exc))
try:
    sum_a = inst_a.summarize()
    print('  incident_store summarize       : OK  total=' + str(sum_a['total']))
except Exception as exc:
    print('  incident_store summarize       : FAIL ' + str(exc))
try:
    sum_b = inst_b.summarize()
    print('  incidentstore  summarize       : OK  total=' + str(sum_b['total']))
except Exception as exc:
    print('  incidentstore  summarize       : FAIL ' + str(exc))

print()
print('=' * 60)
if collisions:
    print('COLLISIONS DETECTED:')
    for c in collisions:
        print('  ' + c)
if missing:
    print('MISSING SYMBOLS:')
    for m in missing:
        print('  ' + m)
if warnings:
    print('WARNINGS:')
    for w in warnings:
        print('  ' + w)
if not collisions and not missing and not warnings:
    print('RESULT: CLEAN — zero collisions, zero missing symbols, zero warnings')
elif not collisions:
    print('RESULT: NO COLLISIONS — review warnings/missing above')
else:
    print('RESULT: FAIL')
print('=' * 60)