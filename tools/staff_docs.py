import base64, glob, html, io, json, os, re, time

SERVER = 'example.com'
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLUE_DIR = os.path.join(ROOT, '资料', '图片')

esc = lambda s: html.escape(str(s))
pinyin = lambda s: s.lower().encode('gb18030', 'replace')
is_test = lambda t: t.startswith('测试')
is_spare = lambda t: re.fullmatch(r'队伍\d+', t) is not None
pw4 = lambda p: f'{p:04d}'

CSS = '''
@page{size:A4;margin:11mm 10mm}
body{font-family:"Microsoft YaHei","PingFang SC",sans-serif;font-size:10pt;line-height:1.5;color:#222;max-width:190mm;margin:0 auto;padding:8px}
h1{font-size:16pt;margin:0}
h2{font-size:12.5pt;margin:16px 0 6px;padding-bottom:2px;border-bottom:1.5px solid #8a3b00;color:#8a3b00}
h3{font-size:11pt;margin:10px 0 4px}
p{margin:4px 0} ul,ol{margin:4px 0;padding-left:1.6em} li{margin:2px 0}
.meta{color:#666;font-size:9pt}
.warn{color:#a00;font-weight:bold}
.wrap{overflow-x:auto}
table{border-collapse:collapse;width:100%;margin:4px 0}
th,td{border:1px solid #aaa;padding:3px 5px;vertical-align:top;text-align:left}
th{background:#f3e6cc;white-space:nowrap}
.box{border:1.5px solid #8a3b00;border-radius:4px;padding:6px 10px;margin:8px 0;background:#fffaf0}
.code{font-family:Consolas,monospace;font-weight:bold;letter-spacing:.06em;white-space:nowrap}
.num{width:2em;text-align:right;color:#666}
.ck{width:2.4em;text-align:center;color:#999}
.nw{white-space:nowrap}
.spare td{height:8mm}
.wide{width:32%}
pre{background:#f5f5f5;border:1px solid #ddd;padding:6px 8px;white-space:pre-wrap;font-size:9pt;margin:4px 0}
@media print{h2,h3{break-after:avoid} tr,.q,.box{break-inside:avoid} a{color:inherit;text-decoration:none}}
'''

def page(title, body, extra_css=''):
    return (f'<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1"><title>{esc(title)}</title>'
            f'<style>{CSS}{extra_css}</style></head><body>{body}</body></html>')

def thumb(path, side=600):
    from PIL import Image, ImageOps
    im = ImageOps.exif_transpose(Image.open(path)).convert('RGB')
    im.thumbnail((side, side), Image.Resampling.LANCZOS)
    buf = io.BytesIO()
    im.save(buf, 'JPEG', quality=62, optimize=True)
    return 'data:image/jpeg;base64,' + base64.b64encode(buf.getvalue()).decode('ascii')

def write(out_dir, *, title, panels, teams, people, verify, api, admin_salt, admin_iter):
    dashboard(os.path.join(out_dir, '进度看板.html'), title=title, api=api, salt=admin_salt, iter=admin_iter)
    stamp = time.strftime('%Y-%m-%d %H:%M')
    real = [t for t in teams if not is_test(t) and not is_spare(t)]
    spare = [t for t in teams if is_spare(t)]
    members = {t: [r['姓名'].strip() for r in rows] for t, rows in teams.items()}
    pws = {}
    for t, name, pw in people:
        pws.setdefault(t, {})[name] = pw
    n_people = sum(len(members[t]) for t in real)
    admin_url, admin_alt = f'{api[0]}/api/admin', f'{api[-1]}/api/admin'

    def pw_cell(t):
        vals = list(pws[t].values())
        main = max(set(vals), key=vals.count)
        odd = ''.join(f'<br><small>{esc(n)} <span class="code">{pw4(p)}</span></small>' for n, p in pws[t].items() if p != main)
        return f'<span class="code">{pw4(main)}</span>{odd}'

    order = sorted(real, key=pinyin)
    ck = '<td class="ck">☐</td>'
    none = '<tr><td colspan="9">（名单还没导入）</td></tr>'
    summary = f'{len(real)} 队 {n_people} 人，另有备用队 {len(spare)} 队'

    sign_rows = ''.join(
        f'<tr><td class="num">{i}</td><td><b>{esc(t)}</b></td><td>{esc("、".join(members[t]))}</td>'
        f'<td>{pw_cell(t)}</td>{ck}</tr>' for i, t in enumerate(order, 1))
    sign_spare = ''.join(
        f'<tr><td class="nw"><b>{esc(t)}</b></td><td class="nw">{esc("、".join(members[t]))}</td><td>{pw_cell(t)}</td>'
        f'<td class="wide"></td>{ck}</tr>' for t in spare)
    sign = f'''
<h1>{esc(title)} · 签到表</h1>
<p class="meta">生成于 {stamp} · {summary} · <span class="warn">含登录口令，仅限工作人员</span></p>
<p>按队名签到：找到本队，勾「签到」，发任务书。登录用姓名 + 口令（全队学号后四位之和，不足四位前面补 0；输不输前面的 0 都能登录），忘了可以在这里查。</p>
<h2>各队（{len(real)} 队）</h2>
<div class="wrap"><table><thead><tr><th>#</th><th>队名</th><th>成员</th><th>口令</th><th>签到</th></tr></thead>
<tbody>{sign_rows or none}</tbody></table></div>
<h2>备用队（{len(spare)} 队，现场补报用）</h2>
<p>没报名的整队：挑一队没用过的，每人分一个花名，口令是这队的口令，在表上写下实际队名和成员。</p>
<div class="wrap"><table><thead><tr><th>队名</th><th>花名（每人一个）</th><th>口令</th><th>实际队名 / 成员</th><th>签到</th></tr></thead>
<tbody class="spare">{sign_spare}</tbody></table></div>
'''
    with open(os.path.join(out_dir, '签到表.html'), 'w', encoding='utf-8') as f:
        f.write(page('签到表（工作人员）', sign))

    checks = ck * 2 + '<td class="ck"></td>'
    heads = '<th>核对</th><th>求助</th><th>明信片</th>'
    check_rows = ''.join(
        f'<tr><td class="num">{i}</td><td><b>{esc(t)}</b></td><td>{esc("、".join(members[t]))}</td>'
        f'<td class="code">{verify[t]}</td>{checks}</tr>' for i, t in enumerate(order, 1))
    check_spare = ''.join(
        f'<tr><td class="nw"><b>{esc(t)}</b></td><td>{esc("、".join(members[t]))}</td>'
        f'<td class="code">{verify[t]}</td>{checks}</tr>' for t in spare)
    desk = f'''
<h1>{esc(title)} · 核对表</h1>
<p class="meta">生成于 {stamp} · {summary} · <span class="warn">含核验码，仅限工作人员</span></p>
<p>回到 C 楼的队伍出示终章页：队名对得上、核验码一致 → 勾「核对」，发明信片和邮票（「明信片」栏写张数）。每队有且仅有一次求助，帮过就勾「求助」。</p>
<h2>各队（{len(real)} 队）</h2>
<div class="wrap"><table><thead><tr><th>#</th><th>队名</th><th>成员</th><th>核验码</th>{heads}</tr></thead>
<tbody>{check_rows or none}</tbody></table></div>
<h2>备用队（{len(spare)} 队，终章上显示的就是这里的队名）</h2>
<div class="wrap"><table><thead><tr><th>队名</th><th>花名</th><th>核验码</th>{heads}</tr></thead>
<tbody class="spare">{check_spare}</tbody></table></div>
'''
    with open(os.path.join(out_dir, '核对表.html'), 'w', encoding='utf-8') as f:
        f.write(page('核对表（工作人员）', desk))

    cards = []
    for p in panels:
        if not p['questions']:
            continue
        rule = f'（{len(p["questions"])} 题，答对 {p["threshold"]} 题过关）' if p['threshold'] < len(p['questions']) else ''
        cards.append(f'<h3>{esc(p["label"])}{rule}</h3>')
        for q in p['questions']:
            alts = '、'.join(q.get('alts') or [])
            figs = [(q['image'], '题目图（玩家看到的）')] if q.get('image') else []
            clues = sorted(glob.glob(os.path.join(CLUE_DIR, q['id'] + '_线索*.jpg')))
            figs += [(c, '答案线索' + (f' {i}' if len(clues) > 1 else '')) for i, c in enumerate(clues, 1)]
            fig = ''.join(f'<figure><img src="{thumb(path)}"><figcaption>{cap}</figcaption></figure>' for path, cap in figs)
            cards.append(f'''<div class="q"><div class="qt"><p><b class="qid">{esc(q["id"])}</b>{esc(q["prompt"])}</p>
<p class="fmt">格式：{esc(q.get("format") or "")}</p>
<p class="ans">答案：<b>{esc(q["answer"])}</b>{f"<small>也收：{esc(alts)}</small>" if alts else ""}</p></div>
<div class="figs">{fig}</div></div>''')

    manual = f'''
<h1>{esc(title)} · 值班手册</h1>
<p class="meta">生成于 {stamp}；题目、名单改了会重新生成。<span class="warn">含全部答案，仅限工作人员；勿外传、勿发群。</span></p>

<div class="box">
<h3>连接服务器</h3>
<p><b>后台网页</b>（看进度、改进度、增删队伍、日志）：电脑、手机都行，两种打开方式内容一样——</p>
<ul>
<li>浏览器打开 <code>{esc(admin_url)}</code>（打不开就用 <code>{esc(admin_alt)}</code>）；</li>
<li>或者双击本文件夹里的 <code>进度看板.html</code>（几个服务器地址自动轮流试）。</li>
</ul>
<p>进去要输<b>后台密码</b>，向技术要（不印在手册上）。勾「记住这台设备」下次免输；公用电脑别勾，用完点「退出」。</p>
<p>在后台「编辑」里取消某题，只删服务器上的记录：手机每次联网都把本机答对的题全部上报一遍，那台手机上还答着这题的话，约 1 分钟内会自己补回来。要彻底取消，先在那台手机上点「清除进度和账号」，再到后台取消。</p>
<p><b>命令行</b>（技术，要用已登记的 SSH 密钥）：</p>
<pre>ssh root@{SERVER}
systemctl status orient            # 服务状态
systemctl restart orient           # 重启服务
journalctl -u orient -n 50         # 最近日志
cd /opt/orient && sudo -u orient python3 app.py list            # 各队进度
cd /opt/orient && sudo -u orient python3 app.py log 100         # 最近 100 条日志
cd /opt/orient && sudo -u orient python3 app.py import teams.csv  # 重新导入名单（增量，不清进度）</pre>
<p>服务器挂了<b>不影响答题和核对</b>（核验码在手机上算），只影响全场进度和后台，修好后手机会自动补报。服务器上的 Java 进程别动。</p>
</div>

<h2>一、题目与答案</h2>
<p>判定时空格、标点、大小写、全半角一律忽略；「也收」是另外认可的写法。每题附题目图（玩家看到的）和答案线索（出题时在现场拍的，答案就在图里）。</p>
{"".join(cards)}

<h2>二、常见问题</h2>
<table><tr><th style="width:34%">玩家说</th><th>怎么办</th></tr>
<tr><td>点开是一堆代码、白屏、没反应</td><td>在微信里直接预览了。安卓：右上角「…」→「用其他应用打开」→ 选浏览器；苹果：用 QQ 浏览器打开。</td></tr>
<tr><td>「当前浏览器版本过旧」</td><td>换 Chrome、手机自带浏览器或 QQ 浏览器。</td></tr>
<tr><td>底部红条「存不了进度」</td><td>无痕模式或浏览器禁止存储。照样能玩，但页面一关就得重答；尽快换浏览器。</td></tr>
<tr><td>「姓名或口令不对」</td><td>查签到表：姓名要和报名时一样（空格不影响）；口令是全队学号后四位之和（如 1234 + 5678 + 42 = 6954），不足四位前面补 0，输不输前面的 0 都行；备用队是表上的花名和口令。确认是本人后直接把口令告诉对方。</td></tr>
<tr><td>「试太多次了，N 秒后再试」</td><td>1 分钟内错了 5 次，等一会儿再试。答题也一样（按题算）。</td></tr>
<tr><td>名单上没有我</td><td>队友报了名 → 用队友的姓名和口令登录（同一个账号可以在好几台手机上登录）。
整队没报名 → 从签到表的备用队表挑一队没用过的，每人分一个花名，口令是这队的口令；在签到表上写下实际队名和成员。
终章上显示的队名是「队伍07」这样的备用队名，核对时按它在核对表上查；后台里可以把这队改成「队伍07·实际队名」（编辑 → 队名）。</td></tr>
<tr><td>想求助</td><td>每队有且仅有一次。先看核对表上这队的「求助」栏：没勾 → 帮一次并勾上（线上帮的，告诉核对桌勾上）；已勾 → 说明规则，婉拒。</td></tr>
<tr><td>队友手机上的进度和我不一样</td><td>正常：同队手机之间不同步，各答各的。核对只看任意一台通关的手机。</td></tr>
<tr><td>换了手机 / 浏览器、清了缓存，进度没了</td><td>进度只存在原来那个浏览器里，回原浏览器再登录就能恢复。回不去：在后台看本队已经上报过哪些题（蓝格），把这些题的答案告诉他们重新输入。</td></tr>
<tr><td>手机要借给别人用 / 想换个账号从头来</td><td>只是换人登录：右上角状态灯 →「退出登录」，本队进度留在这台手机上，再登录会恢复。要彻底删掉：同一处点「清除进度和账号」（确认两次），本机进度和登录信息全删、无法恢复；已经上报到服务器的记录不受影响。</td></tr>
<tr><td>确定答对了却说「不对」</td><td>先看题面下方的格式要求；空格、标点、大小写、全半角都不影响。对照第一章：只是写法不同又确实说得通 → 告诉他按表上的写法输入，并报总负责。</td></tr>
<tr><td>「……还没解锁」</td><td>输入的是还没解锁的区的题号。先在当前区答对 4 题。</td></tr>
<tr><td>这区有一题实在找不到</td><td>每区答对 4 题就解锁下一区，剩下那题可以跳过；以后想起来随时回去答。</td></tr>
<tr><td>右上角状态灯灰 / 红、「暂时连不上服务器」</td><td>不影响答题和核对，恢复联网后自动补报。</td></tr>
<tr><td>「服务器上找不到你的队伍」</td><td>服务器没导入最新名单，或这队在后台被删了，报技术（见开头「连接服务器」）；不影响答题和核对。</td></tr>
<tr><td>终章「还有 N 题未上报」</td><td>不影响核对。</td></tr>
</table>
'''
    manual_css = '''
.box h3{margin:0 0 4px;color:#8a3b00}
.q{border:1px solid #ccc;border-radius:4px;margin:6px 0;padding:5px 8px}
.qid{font-size:12pt;color:#8a3b00;margin-right:.6em}
.figs{display:flex;flex-wrap:wrap;gap:8px;margin-top:4px}
figure{margin:0} figure img{height:48mm;max-width:66mm;object-fit:contain;display:block;border:1px solid #ccc;background:#f5f5f5}
figcaption{font-size:8.5pt;color:#666;text-align:center}
.ans b{color:#8a3b00;font-size:11pt} .ans small{display:block;color:#666}
.fmt{color:#555;font-size:9pt}
code{font-family:Consolas,monospace;background:#f3f3f3;padding:0 2px}
@media (max-width:600px){figure{flex:1 1 45%} figure img{height:auto;max-width:100%;width:100%}}
'''
    with open(os.path.join(out_dir, '值班手册.html'), 'w', encoding='utf-8') as f:
        f.write(page('值班手册（工作人员）', manual, manual_css))


ADMIN_HTML = os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, 'server', 'admin.html')

def dashboard(path, *, title, api, salt, iter):
    with open(ADMIN_HTML, encoding='utf-8') as f:
        src = f.read()
    cfg = json.dumps({'api': api, 'salt': salt, 'iter': iter}, ensure_ascii=False).replace('</', '<\\/')
    with open(path, 'w', encoding='utf-8') as f:
        f.write(src.replace('__TITLE__', esc(title)).replace('__CFG__', cfg))
