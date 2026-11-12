import base64, csv, hashlib, hmac, html, json, os, re, secrets, sqlite3, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

HERE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get('ORIENT_DB', os.path.join(HERE, 'orient.db'))
Q_PATH = os.environ.get('ORIENT_QUESTIONS', os.path.join(HERE, 'questions.json'))
ADMIN_PAGE = os.path.join(HERE, 'admin.html')
HOST, PORT = '127.0.0.1', int(os.environ.get('ORIENT_PORT', '8090'))

MAX_BODY = 4096
MAX_SOLVES = 64
STATS_TTL = float(os.environ.get('ORIENT_STATS_TTL', '10'))
POLL_NEXT = 45
BUCKET_CAP, BUCKET_RATE = 6.0, 1 / 8
IP_CAP, IP_RATE = 60.0, 3.0
BAD_CODE_CAP, BAD_CODE_RATE = 10.0, 1 / 30
ADMIN_CAP, ADMIN_RATE = 30.0, 2.0
ADMIN_SKEW = 300
LOG_KEEP = 20000
AUDIT_KEEP = 5000
AUDIT = ('admin', 'start')
LOG_GROUPS = {'solve': ('solve', 'first'), 'warn': ('bad_proof', 'unknown_code', 'slow', 'admin_fail'),
              'admin': ('admin', 'admin_fail', 'start')}
LOG_PAGE = 200
TEAM_ALPHA = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'

def load_questions():
    with open(Q_PATH, encoding='utf-8') as f:
        q = json.load(f)
    by_qid = {item['id']: bytes.fromhex(item['prf']) for p in q['panels'] for item in p['questions']}
    return q, by_qid

QDATA, QIDX = load_questions() if os.path.exists(Q_PATH) else ({'panels': []}, {})
QORDER = [x['id'] for p in QDATA['panels'] for x in p['questions']]
_k = str(QDATA.get('admin') or '')
ADMIN_KEY = bytes.fromhex(_k) if QDATA.get('adminSalt') and re.fullmatch(r'[0-9a-f]{64}', _k) else None

_db_lock = threading.Lock()
_db = sqlite3.connect(DB_PATH, check_same_thread=False, isolation_level=None)
_db.execute('PRAGMA journal_mode=WAL')
_db.execute('PRAGMA synchronous=NORMAL')
_db.executescript('''
CREATE TABLE IF NOT EXISTS teams (code TEXT PRIMARY KEY, name TEXT NOT NULL, last_seen INTEGER,
  test INTEGER NOT NULL DEFAULT 0, members TEXT NOT NULL DEFAULT '', verify TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS solves (
  code TEXT NOT NULL, qid TEXT NOT NULL, at INTEGER NOT NULL, recv INTEGER NOT NULL,
  PRIMARY KEY (code, qid));
CREATE TABLE IF NOT EXISTS flags (
  code TEXT NOT NULL, qid TEXT, why TEXT NOT NULL, ip TEXT, at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS log (
  id INTEGER PRIMARY KEY, at INTEGER NOT NULL, ip TEXT NOT NULL DEFAULT '', kind TEXT NOT NULL,
  team TEXT NOT NULL DEFAULT '', detail TEXT NOT NULL DEFAULT '');
CREATE INDEX IF NOT EXISTS log_kind ON log (kind);
''')
for t, col in (('teams', "test INTEGER NOT NULL DEFAULT 0"), ('teams', "members TEXT NOT NULL DEFAULT ''"),
               ('teams', "verify TEXT NOT NULL DEFAULT ''")):
    try:
        _db.execute(f'ALTER TABLE {t} ADD COLUMN {col}')
    except sqlite3.OperationalError:
        pass

def q(sql, args=()):
    with _db_lock:
        return _db.execute(sql, args).fetchall()

def tx(stmts):
    with _db_lock:
        _db.execute('BEGIN')
        try:
            for sql, args in stmts:
                _db.execute(sql, args)
        except Exception:
            _db.execute('ROLLBACK')
            raise
        _db.execute('COMMIT')

class Buckets:
    def __init__(self, cap, rate, max_keys=20000):
        self.cap, self.rate, self.max_keys = cap, rate, max_keys
        self.d, self.lock = {}, threading.Lock()
    def take(self, key, n=1.0):
        now = time.monotonic()
        with self.lock:
            tok, t = self.d.get(key, (self.cap, now))
            tok = min(self.cap, tok + (now - t) * self.rate)
            ok = tok >= n
            self.d[key] = (tok - n if ok else tok, now)
            if len(self.d) > self.max_keys:
                self.d.clear()
            return ok

code_buckets = Buckets(BUCKET_CAP, BUCKET_RATE)
ip_buckets = Buckets(IP_CAP, IP_RATE)
bad_code_buckets = Buckets(BAD_CODE_CAP, BAD_CODE_RATE)
admin_buckets = Buckets(ADMIN_CAP, ADMIN_RATE)
log_buckets = Buckets(3, 1 / 60)

_log_n = [0]

def log(kind, ip='', team='', detail=''):
    q('INSERT INTO log (at, ip, kind, team, detail) VALUES (?,?,?,?,?)', (int(time.time()), ip or '', kind, team or '', detail))
    _log_n[0] += 1
    if _log_n[0] % 200 == 0:
        prune_log()

def prune_log():
    marks = ','.join('?' * len(AUDIT))
    for keep, op in ((LOG_KEEP, 'NOT IN'), (AUDIT_KEEP, 'IN')):
        q(f'DELETE FROM log WHERE id IN (SELECT id FROM log WHERE kind {op} ({marks}) ORDER BY id DESC LIMIT -1 OFFSET ?)',
          (*AUDIT, keep))

def log_some(kind, ip, team='', detail='', key=None):
    if log_buckets.take(kind + '|' + (key or ip)):
        log(kind, ip, team, detail)

def log_page(a, n=LOG_PAGE):
    where, args = [], []
    g = LOG_GROUPS.get(a.get('g'))
    if g:
        where.append(f'kind IN ({",".join("?" * len(g))})')
        args += g
    kw = a.get('kw')
    kw = clean(kw[:40], 40) if isinstance(kw, str) else ''
    if kw:
        pat = '%' + re.sub(r'([\\%_])', r'\\\1', kw) + '%'
        where.append("(team LIKE ? ESCAPE '\\' OR detail LIKE ? ESCAPE '\\' OR ip LIKE ? ESCAPE '\\')")
        args += [pat] * 3
    before = a.get('before')
    if isinstance(before, int) and not isinstance(before, bool):
        where.append('id < ?')
        args.append(before)
    rows = q('SELECT id, at, ip, kind, team, detail FROM log' + (' WHERE ' + ' AND '.join(where) if where else '') +
             ' ORDER BY id DESC LIMIT ?', (*args, n + 1))
    return {'log': [{'id': i, 'at': at, 'ip': ip, 'kind': k, 'team': t, 'detail': d} for i, at, ip, k, t, d in rows[:n]],
            'more': len(rows) > n}

def team_name(code):
    row = q('SELECT name FROM teams WHERE code=?', (code,))
    return row[0][0] if row else ''

_stats_cache = {'t': 0.0, 'v': None}
_stats_lock = threading.Lock()

def team_progress(solved):
    done, last = {}, 0
    for p in QDATA['panels']:
        if not p.get('stat'):
            continue
        ats = sorted(solved[x['id']] for x in p['questions'] if x['id'] in solved)
        th = p['threshold'] or len(p['questions'])
        done[p['id']] = ats[th - 1] if len(ats) >= th else None
    if done and all(done.values()):
        last = max(done.values())
    return done, (last or None)

def compute_stats():
    test = {c for (c,) in q('SELECT code FROM teams WHERE test=1')}
    names = dict(q('SELECT code, name FROM teams'))
    per_team, per_q = {}, {}
    total = 0
    for code, qid, at in q('SELECT code, qid, at FROM solves'):
        if code in test or qid not in QIDX:
            continue
        per_team.setdefault(code, {})[qid] = at
        per_q[qid] = per_q.get(qid, 0) + 1
        total += 1
    panel_done = {p['id']: 0 for p in QDATA['panels'] if p.get('stat')}
    finished = []
    for code, solved in per_team.items():
        done, fin = team_progress(solved)
        for pid, t in done.items():
            if t:
                panel_done[pid] += 1
        if fin:
            finished.append((fin, names.get(code, '?')))
    finished.sort()
    return {
        'now': int(time.time()),
        'teams': len(names) - len(test),
        'active': len(per_team),
        'solvedTotal': total,
        'panels': panel_done,
        'questions': per_q,
        'finished': [{'name': n, 'at': t} for t, n in finished[:20]],
        'finishedCount': len(finished),
    }

def get_stats():
    now = time.monotonic()
    if _stats_cache['v'] is not None and now - _stats_cache['t'] < STATS_TTL:
        return _stats_cache['v']
    with _stats_lock:
        if _stats_cache['v'] is None or time.monotonic() - _stats_cache['t'] >= STATS_TTL:
            _stats_cache['v'] = compute_stats()
            _stats_cache['t'] = time.monotonic()
    return _stats_cache['v']

def answer_proof(prf, code):
    return hmac.new(prf, ('proof|' + code).encode('utf-8'), hashlib.sha256).digest()[:16].hex()

def handle_sync(body, ip):
    code = body.get('code')
    if not isinstance(code, str) or not (4 <= len(code) <= 16):
        return 400, {'ok': False, 'err': 'bad_code'}
    code = code.strip().upper()
    if not code_buckets.take(code):
        log_some('slow', ip, team_name(code), '这队上报太频繁，让它等一会儿')
        return 429, {'ok': False, 'err': 'slow_down', 'retry': 15}
    row = q('SELECT name, last_seen FROM teams WHERE code=?', (code,))
    if not row:
        if not bad_code_buckets.take(ip):
            log_some('slow', ip, '', '错误队伍码太多，暂停这个 IP')
            return 429, {'ok': False, 'err': 'slow_down', 'retry': 60}
        log_some('unknown_code', ip, '', f'服务器上没有队伍码 {code[:3]}…（队被删了，或没导入新的 teams.csv）')
        return 403, {'ok': False, 'err': 'unknown_code'}
    name, seen = row[0]
    now = int(time.time())
    have = dict(q('SELECT qid, at FROM solves WHERE code=?', (code,)))

    solves = body.get('solves') or []
    if not isinstance(solves, list) or len(solves) > MAX_SOLVES:
        return 400, {'ok': False, 'err': 'bad_solves'}
    acked, rejected, new = [], [], []
    for s in solves:
        if not isinstance(s, dict):
            continue
        qid, proof, at = s.get('qid'), s.get('proof'), s.get('at')
        if not isinstance(qid, str) or not isinstance(proof, str) or qid not in QIDX:
            continue
        if not hmac.compare_digest(answer_proof(QIDX[qid], code), proof.lower()):
            if qid not in rejected:
                rejected.append(qid)
            continue
        at = at if isinstance(at, int) and now - 6 * 3600 <= at <= now else now
        if qid not in have or at < have[qid]:
            q('INSERT INTO solves (code, qid, at, recv) VALUES (?,?,?,?) '
              'ON CONFLICT(code, qid) DO UPDATE SET at=MIN(at, excluded.at)', (code, qid, at, now))
        if qid not in acked:
            acked.append(qid)
        if qid not in have:
            new.append(qid)
        have[qid] = min(at, have.get(qid, at))
    q('UPDATE teams SET last_seen=? WHERE code=?', (now, code))
    if rejected:
        tx([('INSERT INTO flags (code, qid, why, ip, at) SELECT ?,?,?,?,? '
             'WHERE NOT EXISTS (SELECT 1 FROM flags WHERE code=? AND qid=? AND why=?)',
             (code, x, 'bad_proof', ip, now, code, x, 'bad_proof')) for x in rejected])
        log_some('bad_proof', ip, name, f'{"、".join(rejected)} 的答对证明不对，没记（多半是手机上的网页版本旧了）', key=code)
    if seen is None:
        log('first', ip, name, '第一次联网上报')
    if new:
        new.sort(key=QORDER.index)
        log('solve', ip, name, f'{"、".join(new)}（服务器上本队共 {len(have)} 题）')
    return 200, {'ok': True, 'team': name, 'acked': acked, 'rejected': rejected,
                 'stats': get_stats(), 'next': POLL_NEXT}

def admin_data(a):
    solves, flags = {}, {}
    for code, qid, at in q('SELECT code, qid, at FROM solves'):
        if qid in QIDX:
            solves.setdefault(code, {})[qid] = at
    for code, n in q('SELECT code, COUNT(*) FROM flags GROUP BY code'):
        flags[code] = n
    teams = []
    for code, name, test, members, verify, seen in q(
            'SELECT code, name, test, members, verify, last_seen FROM teams ORDER BY test, name'):
        s = solves.get(code, {})
        done, fin = team_progress(s)
        teams.append({'code': code, 'name': name, 'members': members, 'test': bool(test), 'verify': verify,
                      'solved': s, 'done': done, 'fin': fin, 'flags': flags.get(code, 0), 'seen': seen})
    return {
        'ok': True, 'now': int(time.time()), 'stats': compute_stats(),
        'panels': [{'id': p['id'], 'label': p['label'], 'stat': bool(p.get('stat')),
                    'qids': [x['id'] for x in p['questions']]} for p in QDATA['panels']],
        'teams': teams,
        **log_page(a),
        'logCounts': dict(q('SELECT kind, COUNT(*) FROM log GROUP BY kind')),
    }

def clean(v, n):
    if not isinstance(v, str):
        return None
    v = re.sub(r'[\x00-\x1f\x7f]', '', v).strip()
    return v if len(v) <= n else None

def qid_list(v):
    if not isinstance(v, list) or not all(isinstance(x, str) and x in QIDX for x in v):
        return None
    return sorted(set(v), key=QORDER.index)

def bad(msg):
    return 400, {'ok': False, 'err': 'bad', 'msg': msg}

def op_team_save(a, ip):
    code, name, members = a.get('code') or '', clean(a.get('name'), 40), clean(a.get('members') or '', 200)
    add, remove, test = qid_list(a.get('add') or []), qid_list(a.get('remove') or []), bool(a.get('test'))
    if not isinstance(code, str) or name is None or members is None or add is None or remove is None:
        return bad('参数不对，刷新页面再试')
    if not name:
        return bad('队名不能为空')
    if q('SELECT 1 FROM teams WHERE name=? AND code<>?', (name, code)):
        return bad(f'已经有叫「{name}」的队了，换个名字')
    stmts, what = [], []
    if code:
        row = q('SELECT name, members, test FROM teams WHERE code=?', (code,))
        if not row:
            return bad('这队已经不在了（可能刚被删了），刷新一下')
        old, old_members, old_test = row[0]
        if name != old:
            what.append(f'队名「{old}」→「{name}」')
        if members != old_members:
            what.append(f'成员「{old_members}」→「{members}」')
        if test != bool(old_test):
            what.append('标成测试账号' if test else '取消测试账号')
        stmts.append(('UPDATE teams SET name=?, members=?, test=? WHERE code=?', (name, members, int(test), code)))
    else:
        while True:
            code = ''.join(secrets.choice(TEAM_ALPHA) for _ in range(8))
            if not q('SELECT 1 FROM teams WHERE code=?', (code,)):
                break
        what.append('新建队伍' + (f'，成员「{members}」' if members else '') + ('（测试账号）' if test else ''))
        stmts.append(('INSERT INTO teams (code, name, test, members, verify) VALUES (?,?,?,?,?)',
                      (code, name, int(test), members, '')))
    have = {x for (x,) in q('SELECT qid FROM solves WHERE code=?', (code,))}
    add, remove = [x for x in add if x not in have], [x for x in remove if x in have]
    now = int(time.time())
    stmts += [('INSERT OR IGNORE INTO solves (code, qid, at, recv) VALUES (?,?,?,?)', (code, x, now, now)) for x in add]
    stmts += [('DELETE FROM solves WHERE code=? AND qid=?', (code, x)) for x in remove]
    if add:
        what.append('手动勾上 ' + '、'.join(add))
    if remove:
        what.append('取消 ' + '、'.join(remove))
    if not what:
        return 200, {'ok': True, 'code': code, 'msg': '没有改动'}
    tx(stmts)
    log('admin', ip, name, '；'.join(what))
    return 200, {'ok': True, 'code': code}

def op_team_del(a, ip):
    code = a.get('code')
    row = q('SELECT name FROM teams WHERE code=?', (code,)) if isinstance(code, str) else None
    if not row:
        return bad('这队已经不在了，刷新一下')
    n = q('SELECT COUNT(*) FROM solves WHERE code=?', (code,))[0][0]
    tx([('DELETE FROM solves WHERE code=?', (code,)), ('DELETE FROM flags WHERE code=?', (code,)),
        ('DELETE FROM teams WHERE code=?', (code,))])
    log('admin', ip, row[0][0], f'删除队伍（连同服务器上的 {n} 题进度）')
    return 200, {'ok': True}

def op_flags_clear(a, ip):
    code = a.get('code')
    row = q('SELECT name FROM teams WHERE code=?', (code,)) if isinstance(code, str) else None
    if not row:
        return bad('这队已经不在了，刷新一下')
    n = q('SELECT COUNT(*) FROM flags WHERE code=?', (code,))[0][0]
    q('DELETE FROM flags WHERE code=?', (code,))
    log('admin', ip, row[0][0], f'清除 {n} 条可疑记录')
    return 200, {'ok': True}

ADMIN_OPS = {'team_save': op_team_save, 'team_del': op_team_del, 'flags_clear': op_flags_clear}
_seen, _seen_lock = {}, threading.Lock()

def handle_admin(body, ip):
    if not ADMIN_KEY:
        return 503, {'ok': False, 'err': 'no_admin', 'msg': '服务器上的 questions.json 里没有后台密钥，重新构建并上传'}
    b, m = body.get('b'), body.get('m')
    if not isinstance(b, str) or not isinstance(m, str) or \
            not hmac.compare_digest(hmac.new(ADMIN_KEY, b.encode('utf-8'), hashlib.sha256).hexdigest(), m.lower()):
        if not bad_code_buckets.take('admin|' + ip):
            log_some('slow', ip, '', '后台密码错太多次，暂停这个 IP')
            return 429, {'ok': False, 'err': 'slow_down', 'retry': 60}
        log_some('admin_fail', ip, '', '后台签名不对（密码错，或网页是旧版本）')
        return 403, {'ok': False, 'err': 'auth'}
    m = m.lower()
    try:
        a = json.loads(b)
        t = a['t'] / 1000
    except Exception:
        return bad('请求格式不对')
    now = time.time()
    if not abs(t - now) <= ADMIN_SKEW:
        return 401, {'ok': False, 'err': 'clock', 'now': int(now)}
    with _seen_lock:
        for k in [k for k, v in _seen.items() if now - v > 2 * ADMIN_SKEW]:
            del _seen[k]
        if m in _seen:
            return 409, {'ok': False, 'err': 'replay', 'msg': '重复的请求，已忽略'}
        _seen[m] = now
    op = a.get('op')
    if op == 'data':
        return 200, admin_data(a)
    if op == 'log':
        return 200, {'ok': True, **log_page(a)}
    if op not in ADMIN_OPS:
        return bad('不认识的操作')
    status, obj = ADMIN_OPS[op](a, ip)
    if status == 200:
        _stats_cache['v'] = None
    return status, obj

def admin_page():
    with open(ADMIN_PAGE, encoding='utf-8') as f:
        src = f.read()
    cfg = json.dumps({'api': [''], 'salt': QDATA['adminSalt'], 'iter': QDATA['adminIter']}).replace('</', '<\\/')
    page = src.replace('__TITLE__', html.escape(str(QDATA.get('title') or '校园定向'))).replace('__CFG__', cfg)
    js = page.split('<script>', 1)[1].split('</script>', 1)[0]
    sha = base64.b64encode(hashlib.sha256(js.encode('utf-8')).digest()).decode()
    csp = (f"default-src 'none'; script-src 'sha256-{sha}'; style-src 'unsafe-inline'; connect-src 'self'; "
           "img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
    return page.encode('utf-8'), csp

class Handler(BaseHTTPRequestHandler):
    server_version = 'orient'
    sys_version = ''
    timeout = 10

    def client_ip(self):
        return self.headers.get('X-Real-IP') or self.client_address[0]

    def send_body(self, status, data, ctype, extra=None):
        self.send_response(status)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def send_json(self, status, obj):
        extra = {'Access-Control-Allow-Origin': '*'}
        if status == 429:
            extra['Retry-After'] = str(obj.get('retry', 30))
        data = json.dumps(obj, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
        self.send_body(status, data, 'application/json; charset=utf-8', extra)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.send_header('Access-Control-Max-Age', '86400')
        self.send_header('Content-Length', '0')
        self.end_headers()

    def do_GET(self):
        u = urlsplit(self.path)
        if u.path == '/api/ping':
            return self.send_json(200, {'ok': True, 'now': int(time.time())})
        if u.path == '/api/admin' and ADMIN_KEY:
            if not admin_buckets.take(self.client_ip()):
                return self.send_json(429, {'ok': False, 'err': 'slow_down', 'retry': 10})
            try:
                page, csp = admin_page()
            except Exception as e:
                sys.stderr.write(f'admin page error: {e!r}\n')
                return self.send_json(500, {'ok': False, 'err': 'server'})
            return self.send_body(200, page, 'text/html; charset=utf-8', {
                'Content-Security-Policy': csp, 'X-Frame-Options': 'DENY', 'X-Content-Type-Options': 'nosniff',
                'Referrer-Policy': 'no-referrer', 'X-Robots-Tag': 'noindex'})
        self.send_json(404, {'ok': False})

    def do_POST(self):
        ip = self.client_ip()
        route = {'/api/sync': (ip_buckets, handle_sync), '/api/admin': (admin_buckets, handle_admin)}.get(self.path)
        if not route:
            return self.send_json(404, {'ok': False})
        buckets, handler = route
        if not buckets.take(ip):
            log_some('slow', ip, '', '同一 IP 请求太快，让它等一会儿')
            return self.send_json(429, {'ok': False, 'err': 'slow_down', 'retry': 10})
        try:
            n = int(self.headers.get('Content-Length') or 0)
        except ValueError:
            n = -1
        if n <= 0 or n > MAX_BODY:
            return self.send_json(413, {'ok': False, 'err': 'body'})
        try:
            body = json.loads(self.rfile.read(n).decode('utf-8'))
            if not isinstance(body, dict):
                raise ValueError
        except Exception:
            return self.send_json(400, {'ok': False, 'err': 'json'})
        try:
            status, obj = handler(body, ip)
        except Exception as e:
            sys.stderr.write(f'{self.path} error: {e!r}\n')
            status, obj = 500, {'ok': False, 'err': 'server'}
        self.send_json(status, obj)

    def log_message(self, format, *args):
        pass

class Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 128

def cmd_import(path):
    n = 0
    with open(path, encoding='utf-8-sig') as f:
        for r in csv.DictReader(f):
            code, name = r['code'].strip().upper(), r['name'].strip()
            if code and name:
                q('INSERT INTO teams (code, name, test, members, verify) VALUES (?,?,?,?,?) '
                  'ON CONFLICT(code) DO UPDATE SET name=excluded.name, test=excluded.test, '
                  'members=excluded.members, verify=excluded.verify',
                  (code, name, int(r.get('test') or 0), r.get('members') or '', r.get('verify') or ''))
                n += 1
    print(f'imported {n} teams')

def cmd_list():
    names = dict(q('SELECT code, name FROM teams'))
    cnt = dict(q('SELECT code, COUNT(*) FROM solves GROUP BY code'))
    for code, name in sorted(names.items(), key=lambda kv: -cnt.get(kv[0], 0)):
        print(f'{code}\t{cnt.get(code, 0):3d}\t{name}')
    print(json.dumps(compute_stats(), ensure_ascii=False, indent=1))

def cmd_log(n, kw=''):
    for x in reversed(log_page({'kw': kw}, n)['log']):
        print(f'{time.strftime("%m-%d %H:%M:%S", time.localtime(x["at"]))}  {x["kind"]:<12} {x["team"]:<8} {x["detail"]}  {x["ip"]}')

if __name__ == '__main__':
    cmd = sys.argv[1] if len(sys.argv) > 1 else 'serve'
    if cmd == 'serve':
        print(f'serving on {HOST}:{PORT}, {len(QIDX)} questions', flush=True)
        prune_log()
        log('start', '', '', f'服务启动：{len(QIDX)} 题，{q("SELECT COUNT(*) FROM teams")[0][0]} 队'
                             + ('' if ADMIN_KEY else '；questions.json 里没有后台密钥，后台用不了'))
        Server((HOST, PORT), Handler).serve_forever()
    elif cmd == 'import':
        cmd_import(sys.argv[2])
    elif cmd == 'list':
        cmd_list()
    elif cmd == 'log':
        cmd_log(int(sys.argv[2]) if len(sys.argv) > 2 else 50, ' '.join(sys.argv[3:]))
    else:
        print(__doc__)
