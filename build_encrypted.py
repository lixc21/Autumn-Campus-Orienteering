import os, re, io, csv, json, hashlib, hmac, secrets, base64, sys, unicodedata
from urllib.parse import urlsplit

ROOT = os.path.dirname(os.path.abspath(__file__))
os.chdir(ROOT)
sys.dont_write_bytecode = True
sys.path.insert(0, os.path.join(ROOT, 'tools'))
import staff_docs

P = 2**256 - 189
ITER = 200_000
ADMIN_ITER = 100_000
OUT_HTML = os.path.join('发布', '赏秋校园定向.html')
OUT_SERVER = os.path.join('server', 'questions.json')
OUT_TEAMS = os.path.join('server', 'teams.csv')
STAFF = '工作人员'
SECRETS_PATH = 'build_secrets.json'
ROSTER = '名单.csv'
if os.environ.get('ORIENT_API'):
    OUT_HTML = os.path.join('_test', '本地联调.html')
    OUT_SERVER, OUT_TEAMS = os.path.join('_test', 'questions.json'), os.path.join('_test', 'teams.csv')
    ROSTER = os.environ.get('ORIENT_ROSTER') or ROSTER
    STAFF = None
TEAM_ALPHA = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'

def pbkdf2(pw: bytes, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', pw, salt, ITER, 32)
def sha(b): return hashlib.sha256(b).digest()
def hmac256(k, m): return hmac.new(k, m, hashlib.sha256).digest()
def xor(a, b): return bytes(x ^ y for x, y in zip(a, b))
def b64(b): return base64.b64encode(b).decode('ascii')
def stream_bytes(key, nonce, n):
    out = bytearray()
    ctr = 0
    while len(out) < n:
        out += hashlib.sha256(key + nonce + ctr.to_bytes(4, 'big')).digest()
        ctr += 1
    return bytes(out[:n])
def encrypt(key32: bytes, plaintext: bytes) -> str:
    nonce = secrets.token_bytes(12)
    ks = stream_bytes(key32, nonce, len(plaintext))
    ct = xor(plaintext, ks)
    tag = hmac256(key32, nonce + ct)[:16]
    return b64(nonce + ct + tag)

def norm(s: str) -> str:
    s = unicodedata.normalize('NFKC', s).lower()
    return ''.join(c for c in s if not (c.isspace() or unicodedata.category(c)[0] in 'PSZ'))

def verify_code(verify_key: bytes, team_code: str) -> str:
    v = int.from_bytes(hmac256(verify_key, team_code.encode())[:4], 'big') % 1_000_000
    return f'{v:06d}'

def js_to_json(src: str) -> str:
    out, i, n = [], 0, len(src)
    while i < n:
        c = src[i]
        if src.startswith('//', i):
            while i < n and src[i] != '\n':
                i += 1
        elif c == "'":
            j = i + 1
            buf = []
            while j < n:
                cc = src[j]
                if cc == '\\':
                    buf.append(src[j:j+2]); j += 2; continue
                if cc == "'": break
                if cc == '"': buf.append('\\"')
                else: buf.append(cc)
                j += 1
            out.append('"' + ''.join(buf) + '"')
            i = j + 1
        elif c == '"':
            j = i + 1
            buf = ['"']
            while j < n:
                cc = src[j]
                if cc == '\\':
                    buf.append(src[j:j+2]); j += 2; continue
                buf.append(cc)
                if cc == '"': break
                j += 1
            out.append(''.join(buf)); i = j + 1
        else:
            out.append(c); i += 1
    s = ''.join(out)
    s = re.sub(r'([{\[,]\s*)([A-Za-z_$][\w$]*)(\s*:)', r'\1"\2"\3', s)
    s = re.sub(r',(\s*[}\]])', r'\1', s)
    return s

src = open(os.path.join('网页', 'data.js'), encoding='utf-8').read()
src = re.sub(r'(?s)^.*?window\.GAME_DATA\s*=\s*', '', src).rstrip().rstrip(';').strip()
data = json.loads(js_to_json(src))
panels = data['panels']
pid_set = {p['id'] for p in panels}
all_qids = [q['id'] for p in panels for q in p['questions']]
dups = {x for x in all_qids if all_qids.count(x) > 1}
if dups:
    sys.exit(f'题号重复：{dups}')
if 'LOGIN' in pid_set:
    sys.exit('LOGIN 是保留的面板 id')

S = json.load(open(SECRETS_PATH, encoding='utf-8')) if os.path.exists(SECRETS_PATH) else {}
S.setdefault('gameId', secrets.token_hex(4))
S.setdefault('salt', b64(secrets.token_bytes(16)))
S.setdefault('entry', secrets.token_bytes(32).hex())
S.setdefault('admin', secrets.token_urlsafe(12))
S.setdefault('panels', {})
S.setdefault('teams', {})
S.pop('codes', None)
GLOBAL_SALT = base64.b64decode(S['salt'])
K_ENTRY = bytes.fromhex(S['entry'])

def read_roster():
    if not os.path.exists(ROSTER):
        sys.exit(f'缺少 {ROSTER}（列：队名,姓名,学号后四位,口令）')
    for encoding in ('utf-8-sig', 'gb18030'):
        try:
            with open(ROSTER, encoding=encoding) as f:
                return list(csv.DictReader(f))
        except UnicodeDecodeError:
            continue
    sys.exit(f'{ROSTER} 编码无法识别')

roster = [r for r in read_roster() if (r.get('姓名') or '').strip()]
teams = {}
for r in roster:
    team = (r.get('队名') or '').strip()
    if not team:
        sys.exit(f'{r.get("姓名")} 没有队名')
    teams.setdefault(team, []).append(r)
people = []
for team, rows in teams.items():
    if len(rows) > 4 and not team.startswith('测试'):
        print(f'  ! {team} 有 {len(rows)} 人（超过 4 人）')
    digits = []
    for r in rows:
        d = re.sub(r'\D', '', r.get('学号后四位') or '')
        if not d and not (r.get('口令') or '').strip():
            sys.exit(f'{team}/{r["姓名"]} 既没有学号后四位也没有口令，请补一个数')
        digits.append(int(d) if d else 0)
    team_sum = sum(digits)
    for r in rows:
        pw = re.sub(r'\D', '', r.get('口令') or '')
        people.append((team, r['姓名'].strip(), int(pw) if pw else team_sum))
    if team_sum > 9999:
        print(f'  ! {team} 的口令 {team_sum} 超过四位')
seen = {}
for team, name, pw in people:
    key = (norm(name), pw)
    if not key[0]:
        sys.exit(f'姓名规范化后为空：{name!r}')
    if key in seen:
        sys.exit(f'登录冲突：{name}（{team}）与 {seen[key]} 的姓名+口令相同，请给其中一人换个口令')
    seen[key] = team
for team in teams:
    if team not in S['teams']:
        used = set(S['teams'].values())
        code = None
        while not code or code in used:
            code = ''.join(secrets.choice(TEAM_ALPHA) for _ in range(8))
        S['teams'][team] = code

with open(SECRETS_PATH, 'w', encoding='utf-8') as f:
    json.dump(S, f, ensure_ascii=False, indent=1)

def is_test(team): return team.startswith('测试')

logins = {}
for team, name, pw in people:
    kdf = hashlib.pbkdf2_hmac('sha256', f'{norm(name)}|{pw}'.encode(), GLOBAL_SALT + b'login', ITER, 32)
    rid = sha(kdf + b'id')[:8].hex()
    payload = {'n': name, 't': team, 'c': S['teams'][team], 'k': S['entry']}
    logins[rid] = encrypt(sha(kdf + b'key'), json.dumps(payload, ensure_ascii=False).encode())

def compress_image(rel: str, qid: str) -> bytes:
    from PIL import Image, ImageOps
    src_path = os.path.normpath(rel)
    if not os.path.exists(src_path):
        sys.exit(f'{qid} 的图片不存在：{rel}')
    im = ImageOps.exif_transpose(Image.open(src_path)).convert('RGB')
    im.thumbnail((1280, 1280), Image.Resampling.LANCZOS)
    for quality in (74, 66, 58, 50):
        buf = io.BytesIO()
        im.save(buf, 'JPEG', quality=quality, optimize=True, progressive=True)
        if buf.tell() <= 200_000:
            break
    return buf.getvalue()

for p in panels:
    for q in p['questions']:
        for a in [q['answer']] + list(q.get('alts') or []):
            if not norm(a):
                sys.exit(f"{q['id']} 的答案规范化后为空：{a!r}")
        salt = GLOBAL_SALT + p['id'].encode() + b'|' + q['id'].encode()
        prf = pbkdf2(norm(q['answer']).encode(), salt)
        q['_prf'], q['_mask'] = prf, hmac256(prf, b'mask')
        q['check'] = b64(sha(prf + b'check')[:16])
        alts, seen_alt = [], {norm(q['answer'])}
        for a in q.get('alts') or []:
            if norm(a) in seen_alt:
                continue
            seen_alt.add(norm(a))
            pa = pbkdf2(norm(a).encode(), salt)
            alts.append({'c': b64(sha(pa + b'check')[:16]), 'w': b64(xor(prf, hmac256(pa, b'alt|' + q['id'].encode())))})
        q['_alts'] = alts

for p in panels:
    qs = p['questions']
    n = len(qs)
    if n == 0:
        p['_secret'] = None
        p['threshold'] = 0
        continue
    T = p.get('threshold') or n
    if not 1 <= T <= n:
        sys.exit(f"{p['id']} threshold={T} 不合法")
    if p['id'] not in S['panels']:
        S['panels'][p['id']] = format(int.from_bytes(secrets.token_bytes(32), 'big') % P, '064x')
    secret_int = int(S['panels'][p['id']], 16)
    coeffs = [secret_int] + [secrets.randbelow(P) for _ in range(T - 1)]
    for j, q in enumerate(qs, start=1):
        y = 0
        for k, c in enumerate(coeffs):
            y = (y + c * pow(j, k, P)) % P
        mask = int.from_bytes(q['_mask'], 'big') % P
        q['share_x'] = j
        q['share_enc_y'] = format((y + mask) % P, 'x')
    p['_secret'] = secret_int.to_bytes(32, 'big')
    p['threshold'] = T
with open(SECRETS_PATH, 'w', encoding='utf-8') as f:
    json.dump(S, f, ensure_ascii=False, indent=1)

SECRET_OF = {'LOGIN': K_ENTRY}
for i, p in enumerate(panels):
    req = p.get('requires') or (['LOGIN'] if i == 0 else [panels[i - 1]['id']])
    for r in req:
        if r == 'LOGIN':
            continue
        if r not in pid_set:
            sys.exit(f"{p['id']} requires 未知面板 {r}")
        rp = next(x for x in panels if x['id'] == r)
        if rp['_secret'] is None:
            sys.exit(f"{p['id']} requires 的 {r} 没有题目，无法派生密钥")
        if panels.index(rp) >= i:
            sys.exit(f"{p['id']} requires 的 {r} 必须排在它前面")
    p['requires'] = req
    if p['_secret'] is not None:
        SECRET_OF[p['id']] = p['_secret']

def unlock_key(p):
    return sha(b'unlock|' + b''.join(SECRET_OF[r] for r in p['requires']))

FINALE = next((p for p in panels if p.get('finale')), None)
VERIFY_KEY = sha(b'verify|' + unlock_key(FINALE)) if FINALE else None

imgs = {}
def public_panel(p):
    out = {
        'id': p['id'], 'label': p['label'], 'title': p.get('title'),
        'intro': p.get('intro'), 'info': p.get('info'),
        'finale': p.get('finale', False), 'threshold': p['threshold'],
        'questions': [],
    }
    key = unlock_key(p)
    for q in p['questions']:
        if q.get('image'):
            imgs[q['id']] = encrypt(sha(b'img|' + key + q['id'].encode()), compress_image(q['image'], q['id']))
        out['questions'].append({
            'id': q['id'], 'kind': q['kind'], 'prompt': q['prompt'], 'format': q.get('format'),
            'img': bool(q.get('image')),
            'check': q['check'], 'alts': q['_alts'],
            'x': q['share_x'], 'y': q['share_enc_y'],
        })
    return out

panels_out = []
for p in panels:
    pub = public_panel(p)
    panels_out.append({
        'id': p['id'], 'label': p['label'], 'requires': p['requires'], 'stat': bool(p.get('stat')),
        'finale': bool(p.get('finale')), 'qids': [q['id'] for q in p['questions']],
        'enc': encrypt(unlock_key(p), json.dumps(pub, ensure_ascii=False).encode('utf-8')),
    })

api = data.get('api') or []
if isinstance(api, str):
    api = [api]
if os.environ.get('ORIENT_API'):
    api = [os.environ['ORIENT_API']]
def hide_api(api, game_id):
    raw = json.dumps(api, separators=(',', ':')).encode()
    return b64(bytes(b ^ ord(game_id[i % len(game_id)]) for i, b in enumerate(raw)))

manifest = {
    'title': data.get('title', '赏秋校园定向'),
    'gameId': S['gameId'],
    'ep': hide_api(api, S['gameId']),
    'globalSalt': S['salt'],
    'iter': ITER,
    'P_hex': format(P, 'x'),
    'logins': logins,
    'panels': panels_out,
    'imgs': imgs,
}

ADMIN_SALT = 'orient-admin|' + S['gameId']
server_table = {
    'salt': S['salt'],
    'title': data.get('title', '赏秋校园定向'),
    'admin': hashlib.pbkdf2_hmac('sha256', S['admin'].encode(), ADMIN_SALT.encode(), ADMIN_ITER, 32).hex(),
    'adminSalt': ADMIN_SALT,
    'adminIter': ADMIN_ITER,
    'panels': [{
        'id': p['id'], 'label': p['label'], 'threshold': p['threshold'], 'stat': bool(p.get('stat')),
        'questions': [{'id': q['id'], 'prf': q['_prf'].hex()} for q in p['questions']],
    } for p in panels if p['questions']],
}
os.makedirs(os.path.dirname(OUT_SERVER), exist_ok=True)
with open(OUT_SERVER, 'w', encoding='utf-8') as f:
    json.dump(server_table, f, ensure_ascii=False, indent=1)
with open(OUT_TEAMS, 'w', encoding='utf-8', newline='') as f:
    w = csv.writer(f)
    w.writerow(['code', 'name', 'test', 'members', 'verify'])
    for team, rows in teams.items():
        code = S['teams'][team]
        w.writerow([code, team, int(is_test(team)), '、'.join(r['姓名'].strip() for r in rows),
                    verify_code(VERIFY_KEY, code) if VERIFY_KEY else ''])

css = open(os.path.join('网页', 'styles.css'), encoding='utf-8').read()
app = open(os.path.join('网页', 'app.js'), encoding='utf-8').read()
shell = open(os.path.join('网页', 'shell.html'), encoding='utf-8').read()
manifest_json = json.dumps(manifest, ensure_ascii=False, separators=(',', ':')).replace('</', '<\\/')
title = manifest['title']
out_html = (shell
            .replace('{{TITLE}}', title)
            .replace('{{CSS}}', css)
            .replace('{{APP}}', app)
            .replace('{{MANIFEST}}', manifest_json))
os.makedirs(os.path.dirname(OUT_HTML), exist_ok=True)
with open(OUT_HTML, 'w', encoding='utf-8') as f:
    f.write(out_html)

leaks = [a for p in panels for q in p['questions'] for a in [q['answer']] + list(q.get('alts') or [])
         if len(norm(a)) >= 2 and a in out_html]
if leaks:
    os.remove(OUT_HTML)
    sys.exit(f'!! 分发文件里出现了明文答案：{leaks}，已删除输出')
hosts = [h for h in {urlsplit(a).hostname for a in api} if h and h in out_html]
if hosts:
    os.remove(OUT_HTML)
    sys.exit(f'!! 分发文件里出现了明文服务器地址：{hosts}，已删除输出')

def write_staff():
    os.makedirs(STAFF, exist_ok=True)
    lines = []
    for p in panels:
        for q in p['questions']:
            lines.append(f"{q['id']} {q['answer']}" + (f"（也收：{'、'.join(q['alts'])}）" if q.get('alts') else ''))
    with open(os.path.join(STAFF, '答案速查.txt'), 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')

    with open(os.path.join(STAFF, '登录口令表.csv'), 'w', encoding='utf-8-sig', newline='') as f:
        w = csv.writer(f)
        w.writerow(['队名', '姓名', '口令'])
        w.writerows((t, n, f'="{pw:04d}"') for t, n, pw in people)

    staff_docs.write(STAFF, title=manifest['title'], panels=panels, teams=teams, people=people,
                     verify={t: verify_code(VERIFY_KEY, S['teams'][t]) if VERIFY_KEY else '' for t in teams},
                     api=api, admin_salt=ADMIN_SALT, admin_iter=ADMIN_ITER)

if STAFF:
    write_staff()
else:
    staff_docs.dashboard(os.path.join('_test', '进度看板.html'), title=manifest['title'], api=api, salt=ADMIN_SALT, iter=ADMIN_ITER)

size = os.path.getsize(OUT_HTML)
print(f'OK: {OUT_HTML} ({size:,} bytes)   server -> {OUT_SERVER}, {OUT_TEAMS}   staff -> {STAFF + "/" if STAFF else "（联调版不写）"}')
print(f'  gameId={S["gameId"]}  PBKDF2 iter={ITER}  api={api}')
print(f'  {len(people)} 人 / {len(teams)} 队登录记录，{len(imgs)} 张题图')
print(f'  后台：{api[0]}/api/admin 或 工作人员/进度看板.html，密码是 {SECRETS_PATH} 里的 "admin"（改了要重新构建、上传 questions.json）')
for p in panels:
    print(f"  {p['id']:<4} {len(p['questions']):2d}q T={p['threshold']:<2} requires={p['requires']}{' [stat]' if p.get('stat') else ''}  {p['label']}")
