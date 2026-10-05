/**
 * The eight secret routes of the "All reachable secret routes" outline (MVP-7677), each as one scripted probe the
 * agent runs inside its sandbox. The vitest suites and the Docker integration probe use the same compiled code.
 *
 * Every probe is one Python program (run through the agent's Bash tool) that
 * - tries the route (every sub-command reports its exit status; a failing sub-command fails the row),
 * - writes large dumps in full to `/work` and scans the files themselves, so the runtime's truncation of a tool
 *   output cannot hide a marker (R2-3),
 * - scans with split needles, so the script's own text never holds a marker whole,
 * - carries a positive control: a split-needle canary planted where the agent may read it must be found, so a
 *   scanner that sees nothing cannot pass,
 * - prints one `SEC-REPORT {json}` line holding names, booleans and counts only.
 *
 * The built-in tools of the route (Read, Grep, Glob) are separate steps whose results the model-bound surfaces scan.
 */
import {
  chatTurn,
  credentialProblems,
  splitNeedles,
  turnProblems,
  type SecurityMarkers,
  type SecurityRig,
  type ToolStep,
  type TurnObservation,
} from "./security-matrix.js";

export type RouteId = "env" | "proc" | "config" | "repo" | "session" | "legacy" | "links" | "routing";

export const ROUTE_IDS: RouteId[] = ["env", "proc", "config", "repo", "session", "legacy", "links", "routing"];

export interface RouteContext {
  markers: SecurityMarkers;
  /** Host paths of trusted files: the agent must not be able to read them from the sandbox. */
  host: { workspace: string; home: string; persist: string };
  /** The gateway's port (the routing probe sends the relay and proxy tokens to it). */
  gatewayPort: number;
  /** A harmless value the scanners must find in `/work`. */
  canary: string;
  /** `routing`: `probe` runs the attacks and saves the run's relay URL and token; `replay` retries what an earlier run saved. */
  phase?: "probe" | "replay";
  /** `routing` replay after a gateway restart: the old relay listener died with the old process (a refused connection is as dead as a 404). */
  afterRestart?: boolean;
}

export type RouteStep = ToolStep;

export interface RouteReport {
  route: string;
  /** Exit status of every sub-command (0 = ran and succeeded). */
  rc: Record<string, number>;
  /** Marker names with the number of places they were found (empty when nothing leaked). */
  hits: Record<string, number>;
  /** Positive controls and permitted operations: each must be true. */
  controls: Record<string, boolean>;
  /** Anything the route reports as a count or flag (never a value). */
  facts: Record<string, unknown>;
  /** Epoch ms at which the probe started and ended inside the sandbox. */
  t0: number;
  t1: number;
}

export interface RouteVerdict {
  failures: string[];
  /** Names of the controls that held. */
  controls: string[];
  hits: number;
  report: RouteReport | null;
}

/** The marker values and the canary as split needles for the in-sandbox scanner. */
function needlesFor(ctx: RouteContext): string {
  return splitNeedles({ ...ctx.markers.values, canary: ctx.canary });
}

/** The shared Python scanner: split needles, a file scanner, a tree scanner and a sub-command runner with exit status. */
function prelude(ctx: RouteContext): string {
  return String.raw`import json, os, re, subprocess, sys, time
T0 = time.time()
NEEDLES = {k: a + b for k, (a, b) in json.loads(${JSON.stringify(needlesFor(ctx))}).items()}
HITS = {}
RC = {}
CONTROLS = {}
FACTS = {}
def scan_bytes(label, data):
    text = data.replace(b'\0', b' ').decode('utf8', 'replace')
    for k, v in NEEDLES.items():
        if v in text:
            HITS.setdefault(k, []).append(label)
def scan_file(path, limit=8000000):
    try:
        if os.path.islink(path) or os.path.getsize(path) > limit:
            return -1
        with open(path, 'rb') as f:
            data = f.read()
    except Exception:
        return -1
    scan_bytes(path, data)
    return len(data)
def scan_tree(root, skip=()):
    files = 0
    for base, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = [d for d in dirs if os.path.join(base, d) not in skip]
        for n in names:
            if scan_file(os.path.join(base, n)) >= 0:
                files += 1
    return files
def run(name, argv, out=None, timeout=60):
    try:
        r = subprocess.run(argv, capture_output=True, timeout=timeout)
        data = r.stdout + r.stderr
        RC[name] = r.returncode
    except Exception as e:
        data = str(e).encode()
        RC[name] = -1
    scan_bytes('step:' + name, data)
    if out:
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, 'wb') as f:
            f.write(data)
    return data
def plant_canary(directory):
    os.makedirs(directory, exist_ok=True)
    with open(os.path.join(directory, 'canary.txt'), 'w') as f:
        f.write(NEEDLES['canary'])
def finish(route):
    canary = 'canary' in HITS
    CONTROLS['scanner_found_canary'] = canary
    HITS.pop('canary', None)
    print('SEC-REPORT ' + json.dumps({'route': route, 'rc': RC, 'hits': {k: len(v) for k, v in HITS.items()}, 'controls': CONTROLS, 'facts': FACTS, 't0': int(T0 * 1000), 't1': int(time.time() * 1000)}))
`;
}

function python(ctx: RouteContext, body: string): string {
  return `python3 - <<'PY'\n${prelude(ctx)}${body}\nPY`;
}

/* ------------------------------------------------------------------ */
/*  The probes                                                          */
/* ------------------------------------------------------------------ */

const ENV_BODY = String.raw`
D = '/work/route-env'
plant_canary(D)
py = run('python-env', ['python3', '-c', 'import os, json; print(json.dumps(dict(os.environ)))'], D + '/python.txt')
CONTROLS['python_env_shows_sandbox_home'] = b'"HOME": "/home/node"' in py
for name, argv in (('env', ['env']), ('sh-env', ['sh', '-c', 'env']), ('printenv', ['printenv']), ('node-env', ['node', '-e', 'console.log(JSON.stringify(process.env))']), ('perl-env', ['perl', '-e', 'print join("\\n", map {"$_=$ENV{$_}"} keys %ENV)'])):
    data = run(name, argv, D + '/' + name + '.txt')
    CONTROLS[name + '_nonempty'] = len(data) > 100
for p in ('/proc/self/environ', '/proc/%d/environ' % os.getppid()):
    try:
        data = open(p, 'rb').read()
        scan_bytes(p, data)
        CONTROLS['read_' + p.split('/')[2].replace('self', 'own') + '_environ'] = len(data) > 0
    except Exception:
        CONTROLS['read_' + p.split('/')[2].replace('self', 'own') + '_environ'] = False
FACTS['git_config_env_vars'] = len([k for k in os.environ if k.startswith('GIT_CONFIG')])
FACTS['files_scanned'] = scan_tree(D)
CONTROLS['dump_files_scanned'] = FACTS['files_scanned'] >= 7
finish('env')
`;

const PROC_BODY = String.raw`
D = '/work/route-proc'
plant_canary(D)
me = os.getpid()
seen = 0
lines = []
for pid in sorted(int(x) for x in os.listdir('/proc') if x.isdigit()):
    for name in ('environ', 'cmdline'):
        try:
            data = open('/proc/%d/%s' % (pid, name), 'rb').read()
        except Exception:
            continue
        scan_bytes('/proc/%d/%s' % (pid, name), data)
        lines.append('%d %s %d' % (pid, name, len(data)))
        if pid == me and name == 'environ' and len(data) > 0:
            CONTROLS['own_environ_readable'] = True
    seen += 1
with open(D + '/processes.txt', 'w') as f:
    f.write('\n'.join(lines))
FACTS['processes_visible'] = seen
CONTROLS['scanned_own_and_sibling_processes'] = seen >= 2
CONTROLS.setdefault('own_environ_readable', False)
ps = run('ps', ['ps', 'auxww'], D + '/ps.txt')
CONTROLS['ps_listed_processes'] = len(ps) > 100
FACTS['files_scanned'] = scan_tree(D)
finish('proc')
`;

const CONFIG_BODY = String.raw`
D = '/work/route-config'
plant_canary(D)
os.makedirs('/work/decoy', exist_ok=True)
open('/work/decoy/sessions.json', 'w').write('{}')
trusted = ['/home/node/.claude/.credentials.json', '/home/node/.claude/sessions.json', '/home/node/.claude/tools.json', '/home/node/.claude/mcp-servers.json', '/home/node/.mcp.json', '/work/.mcp.json'] + HOSTPATHS
opened = 0
for p in trusted:
    try:
        data = open(p, 'rb').read()
        opened += 1
        scan_bytes(p, data)
    except Exception:
        pass
FACTS['trusted_paths_opened'] = opened
CONTROLS['no_trusted_file_opened'] = opened == 0
names = ('.credentials.json', 'sessions.json', 'tools.json', 'mcp-servers.json', 'id_rsa', 'hosts.yml')
found = 0
for base, dirs, files in os.walk('/', followlinks=False):
    dirs[:] = [d for d in dirs if os.path.join(base, d) not in ('/proc', '/sys', '/dev', '/usr', '/lib', '/lib32', '/lib64', '/libx32', '/bin', '/sbin', '/boot', '/snap')]
    for n in files:
        if n in names and not base.startswith('/work'):
            found += 1
            scan_file(os.path.join(base, n))
FACTS['trusted_names_found_outside_work'] = found
CONTROLS['no_trusted_name_found'] = found == 0
CONTROLS['name_walk_found_decoy'] = os.path.exists('/work/decoy/sessions.json')
FACTS['files_scanned'] = scan_tree('/home/node/.claude') + scan_tree(D)
finish('config')
`;

const REPO_BODY = String.raw`
D = '/work/route-repo'
plant_canary(D)
repo = '/home/node/.claude/projects/repo'
opened = 0
for p in ['/home/node/.ssh/id_rsa', '/home/node/.config/gh/hosts.yml', '/root/.ssh/id_rsa'] + HOSTPATHS:
    try:
        scan_bytes(p, open(p, 'rb').read())
        opened += 1
    except Exception:
        pass
FACTS['credential_files_opened'] = opened
CONTROLS['no_credential_file_opened'] = opened == 0
remote = run('git-remote', ['git', '-C', repo, 'remote', '-v'], D + '/remote.txt')
CONTROLS['git_remote_shows_url_without_token'] = b'github.com/acme/repo.git' in remote and b'x-access-token' not in remote
log = run('git-log', ['git', '-C', repo, 'log', '--oneline'], D + '/log.txt')
CONTROLS['permitted_git_log_ran'] = RC['git-log'] == 0 and len(log) > 0
cfg = run('git-config', ['git', '-C', repo, 'config', '--show-origin', '--list'], D + '/config.txt')
FACTS['git_config_lines'] = len(cfg.splitlines())
for key in ('safe.bareRepository', 'core.fsmonitor', 'core.hooksPath'):
    out = run('git-get-' + key, ['git', 'config', '--show-origin', '--get', key], D + '/get-' + key + '.txt')
    FACTS['git_' + key.replace('.', '_')] = out.decode('utf8', 'replace').strip().split('\t')[0] if out else ''
FACTS['git_config_env_vars'] = len([k for k in os.environ if k.startswith('GIT_CONFIG')])
FACTS['repository_files_scanned'] = scan_tree('/home/node/.claude/projects')
CONTROLS['repository_views_scanned'] = FACTS['repository_files_scanned'] > 0
FACTS['files_scanned'] = scan_tree(D)
finish('repo')
`;

const SESSION_BODY = String.raw`
D = '/work/route-session'
plant_canary(D)
skip_content = ('/proc', '/sys', '/dev', '/usr', '/lib', '/lib32', '/lib64', '/libx32', '/bin', '/sbin', '/boot', '/snap')
other_names = 0
files = 0
for base, dirs, names in os.walk('/', followlinks=False):
    dirs[:] = [d for d in dirs if os.path.join(base, d) not in ('/proc', '/sys', '/dev')]
    top = '/' + base.strip('/').split('/')[0] if base != '/' else '/'
    for n in names:
        if n in ('b-secret.txt', 'b2-secret.txt'):
            other_names += 1
        if top not in skip_content and scan_file(os.path.join(base, n)) >= 0:
            files += 1
FACTS['content_files_scanned'] = files
FACTS['other_session_files_found'] = other_names
CONTROLS['no_other_session_file_found'] = other_names == 0
CONTROLS['walk_covered_many_files'] = files > 20
projects = sorted(os.listdir('/home/node/.claude/projects')) if os.path.isdir('/home/node/.claude/projects') else []
FACTS['transcript_directories'] = len([p for p in projects if p.startswith('-')])
CONTROLS['only_own_transcript_directory'] = all(p == '-work' for p in projects if p.startswith('-'))
FACTS['files_scanned_own'] = scan_tree(D)
finish('session')
`;

const LEGACY_BODY = String.raw`
D = '/work/route-legacy'
plant_canary(D)
found = 0
for base, dirs, names in os.walk('/', followlinks=False):
    dirs[:] = [d for d in dirs if os.path.join(base, d) not in ('/proc', '/sys', '/dev')]
    for n in names:
        if n == 'sdk-legacy.jsonl':
            found += 1
FACTS['legacy_transcript_files_found'] = found
CONTROLS['legacy_transcript_not_visible'] = found == 0
CONTROLS['transcript_directory_listed'] = os.path.isdir('/home/node/.claude/projects')
FACTS['transcript_files_scanned'] = scan_tree('/home/node/.claude/projects') + scan_tree(D)
finish('legacy')
`;

const LINKS_BODY = String.raw`
D = '/work/route-links'
plant_canary(D)
open(D + '/permitted.txt', 'w').write('PERMITTED-OK')
OPENED = []
def attempt(label, path):
    # Returns the number of bytes read, or -1 when the path could not be opened. An empty file (a trusted stand-in the sandbox binds over a planted copy) reads as 0.
    try:
        data = open(path, 'rb').read()
    except Exception:
        return -1
    scan_bytes(label, data)
    if len(data) > 0:
        OPENED.append(label)
    return len(data)
# Traversal out of the approved workspace toward trusted files (a plain read of a permitted file is the control).
for rel in ('../.credentials.json', '../../.claude/.credentials.json', '../home/node/.claude/.credentials.json', '../../../' + HOSTWS.lstrip('/') + '/.credentials.json'):
    attempt('traversal:' + rel, os.path.join('/work', rel))
CONTROLS['traversal_reads_permitted_file'] = attempt('permitted-control', '/work/route-links/../route-links/permitted.txt') > 0
# Links and copies planted before the update, in the global content the agent may read.
for p in ('/home/node/.claude/skills/to-credentials', '/home/node/.claude/skills/to-credentials-relative', '/home/node/.claude/skills/hardlinked-credentials', '/home/node/.claude/memory/copy.md', '/home/node/.claude/projects/linked-home/.ssh/id_rsa'):
    attempt('planted:' + p, p)
# Links the agent creates itself, toward trusted paths, and the same links read again (a later turn reads what an earlier one made).
targets = ['/home/node/.claude/.credentials.json', HOSTWS + '/.credentials.json', HOSTHOME + '/.ssh/id_rsa']
for i, t in enumerate(targets):
    link = '/work/escape-%d' % i
    if not os.path.islink(link):
        try:
            os.symlink(t, link)
        except Exception:
            pass
    attempt('escape-link:%d' % i, link)
try:
    os.symlink('/home/node/.claude/.credentials.json', '/home/node/plant')
except Exception:
    pass
attempt('home-link', '/home/node/plant')
if not os.path.islink('/work/permitted-link'):
    os.symlink('/work/route-links/permitted.txt', '/work/permitted-link')
CONTROLS['permitted_link_inside_work_readable'] = open('/work/permitted-link').read() == 'PERMITTED-OK'
FACTS['trusted_content_obtained_through_links_or_traversal'] = len([l for l in OPENED if l != 'permitted-control'])
FACTS['opened_labels'] = [l for l in OPENED if l != 'permitted-control']
CONTROLS['no_trusted_content_obtained'] = FACTS['trusted_content_obtained_through_links_or_traversal'] == 0
FACTS['files_scanned'] = scan_tree(D)
finish('links')
`;

const ROUTING_BODY = String.raw`
import urllib.request, urllib.error
GATEWAY = 'http://127.0.0.1:%d' % GATEWAY_PORT
PATTERN = re.compile(rb'http://127\.0\.0\.1:\d+/mcp/[A-Za-z0-9_-]+')
def find_urls():
    found = []
    def add(data):
        for m in PATTERN.finditer(data):
            u = m.group(0).decode()
            if u not in found:
                found.append(u)
    for pid in os.listdir('/proc'):
        if not pid.isdigit():
            continue
        for name in ('cmdline', 'environ'):
            try:
                add(open('/proc/%s/%s' % (pid, name), 'rb').read())
            except Exception:
                continue
    for root in ('/tmp', '/home/node'):
        for base, dirs, files in os.walk(root):
            for f in files:
                try:
                    p = os.path.join(base, f)
                    if os.path.getsize(p) > 5000000:
                        continue
                    add(open(p, 'rb').read())
                except Exception:
                    continue
    return found
def proxy_token():
    for pid in os.listdir('/proc'):
        if not pid.isdigit():
            continue
        try:
            data = open('/proc/%s/environ' % pid, 'rb').read().split(b'\0')
        except Exception:
            continue
        for item in data:
            if item.startswith(b'ANTHROPIC_API_KEY='):
                return item.split(b'=', 1)[1].decode()
    return None
def http(method, url, raw=None, headers=None):
    h = {'Content-Type': 'application/json'}
    h.update(headers or {})
    req = urllib.request.Request(url, data=raw, headers=h, method=method)
    try:
        r = urllib.request.urlopen(req, timeout=20)
        return r.status, r.read().decode('utf8', 'replace')
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf8', 'replace')
    except Exception as e:
        return 0, str(e)
def rpc(method, id=1, params=None):
    return json.dumps({'jsonrpc': '2.0', 'id': id, 'method': method, 'params': params or {}}).encode()
CASES = {}
if PHASE == 'replay':
    # What an earlier run saved: its relay URL and its model proxy token must be dead now.
    try:
        old_url = open('/work/route-routing/relay-url').read().strip()
        old_token = open('/work/route-routing/proxy-token').read().strip()
    except Exception:
        old_url, old_token = None, None
    CONTROLS['earlier_run_saved_its_urls'] = old_url is not None
    if old_url:
        s, b = http('POST', old_url, rpc('tools/call', 21, {'name': 'lookup_record', 'arguments': {'id': 'R-1'}}))
        CASES['old-relay-url'] = s
        s, b = http('POST', os.environ.get('ANTHROPIC_BASE_URL', 'http://127.0.0.1:1') + '/v1/messages', b'{"model":"m","max_tokens":1,"messages":[]}', {'x-api-key': old_token})
        CASES['old-proxy-token-model-proxy'] = s
        for route in ('/v1/tools', '/v1/mcp-servers', '/v1/sessions'):
            s, b = http('GET', GATEWAY + route, None, {'Authorization': 'Bearer ' + old_token})
            CASES['old-proxy-token GET ' + route] = s
else:
    D = '/work/route-routing'
    plant_canary(D)
    url = None
    for candidate in find_urls():
        s, b = http('POST', candidate, rpc('tools/list', 99))
        if 'lookup_record' in b:
            url = candidate
            break
    CONTROLS['relay_url_found_where_an_agent_can_read'] = url is not None
    token = proxy_token()
    CONTROLS['proxy_token_found'] = token is not None
    if url:
        open(D + '/relay-url', 'w').write(url)
        relay_token = url.rsplit('/', 1)[1]
        for label, raw, hdr in [
            ('ungranted', rpc('tools/call', 11, {'name': 'delete_record', 'arguments': {}}), None),
            ('unparsable', b'{nope', None),
            ('batch', json.dumps([{'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list'}]).encode(), None),
            ('methodless', json.dumps({'jsonrpc': '2.0', 'id': 5, 'result': {}}).encode(), None),
            ('resources', rpc('resources/read', 12, {'uri': 'file:///etc/passwd'}), None),
            ('changed-authorization', rpc('tools/call', 14, {'name': 'lookup_record', 'arguments': {'id': 'R-1'}}), {'Authorization': 'Bearer AGENT-CHOSEN-7677', 'X-Api-Key': 'AGENT-CHOSEN-7677'}),
        ]:
            s, b = http('POST', url, raw, hdr)
            CASES[label] = s
            FACTS['body_' + label] = b[:400]
        for who, tok in (('relay-token', relay_token), ('proxy-token', token)):
            if tok is None:
                continue
            h = {'Authorization': 'Bearer ' + tok}
            for route in ('/v1/tools', '/v1/mcp-servers', '/v1/auth/status', '/v1/sessions'):
                CASES['%s GET %s' % (who, route)] = http('GET', GATEWAY + route, None, h)[0]
            for route in ('/v1/auth/login', '/v1/query'):
                CASES['%s POST %s' % (who, route)] = http('POST', GATEWAY + route, b'{}', h)[0]
    if token:
        open(D + '/proxy-token', 'w').write(token)
    FACTS['files_scanned'] = scan_tree(D)
FACTS['cases'] = CASES
finish('routing')
`;

const BODIES: Record<RouteId, string> = { env: ENV_BODY, proc: PROC_BODY, config: CONFIG_BODY, repo: REPO_BODY, session: SESSION_BODY, legacy: LEGACY_BODY, links: LINKS_BODY, routing: ROUTING_BODY };

/** The Python source of a route probe, with the host paths and the gateway port filled in. */
export function routeSource(route: RouteId, ctx: RouteContext): string {
  const hostPaths = [`${ctx.host.workspace}/.credentials.json`, `${ctx.host.persist}/sessions.json`, `${ctx.host.persist}/tools.json`, `${ctx.host.persist}/mcp-servers.json`, `${ctx.host.home}/.ssh/id_rsa`, `${ctx.host.home}/.config/gh/hosts.yml`];
  const constants = `HOSTPATHS = ${JSON.stringify(hostPaths)}\nHOSTWS = ${JSON.stringify(ctx.host.workspace)}\nHOSTHOME = ${JSON.stringify(ctx.host.home)}\nGATEWAY_PORT = ${ctx.gatewayPort}\nPHASE = ${JSON.stringify(ctx.phase ?? "probe")}\n`;
  return python(ctx, constants + BODIES[route]);
}

/** The built-in tool steps of a route: the model-bound result is scanned like every other surface. */
function builtinSteps(route: RouteId, ctx: RouteContext): RouteStep[] {
  const trusted = [`${ctx.host.workspace}/.credentials.json`, `${ctx.host.home}/.ssh/id_rsa`, `${ctx.host.persist}/sessions.json`, `${ctx.host.persist}/mcp-servers.json`];
  switch (route) {
    case "config":
      return [
        ...trusted.map((file) => ({ name: "Read", input: { file_path: file } })),
        { name: "Read", input: { file_path: "/home/node/.claude/.credentials.json" } },
        { name: "Grep", input: { pattern: "SYNTH-[A-Z0-9]+-", path: "/home", output_mode: "content" } },
        { name: "Glob", input: { pattern: "**/*credentials*", path: "/home" } },
      ];
    case "repo":
      return [{ name: "Read", input: { file_path: `${ctx.host.home}/.ssh/id_rsa` } }, { name: "Read", input: { file_path: "/home/node/.ssh/id_rsa" } }];
    case "links":
      return [{ name: "Read", input: { file_path: "/work/escape-0" } }, { name: "Read", input: { file_path: "/work/escape-1" } }];
    case "routing":
      // A registered MCP server and a webhook that answer a credential-bearing call with a redirect to another origin.
      return ctx.phase === "replay" ? [] : [{ name: "mcp__moved__get_page", input: { id: "P-9" } }, { name: "mcp__agent-gateway-tools__moved_hook", input: {} }];
    default:
      return [];
  }
}

/** The steps the scripted model runs for a route: the Python probe first, then its built-in tool calls. */
export function routeSteps(route: RouteId, ctx: RouteContext): RouteStep[] {
  return [{ name: "Bash", input: { command: routeSource(route, ctx), description: `route ${route}` } }, ...builtinSteps(route, ctx)];
}

/** The request-scoped steps every route run starts with: a per-user override, a request-body http server and a request-body stdio server. */
export function credentialSteps(): RouteStep[] {
  return [
    { name: "mcp__jira__get_page", input: { id: "P-1" } },
    { name: "mcp__reqhttp__get_page", input: { id: "P-2" } },
    { name: "mcp__reqlocal__echo", input: {} },
  ];
}

/** Extracts the `SEC-REPORT` JSON of a tool result. */
export function parseReport(text: string): RouteReport | null {
  const line = text.split("\n").find((l) => l.startsWith("SEC-REPORT "));
  if (!line) return null;
  try {
    return JSON.parse(line.slice("SEC-REPORT ".length)) as RouteReport;
  } catch {
    return null;
  }
}

/** Exit statuses the routes require (every other sub-command's exit status is only reported). */
const MUST_SUCCEED: Record<RouteId, string[]> = {
  env: ["python-env", "env", "sh-env", "printenv", "node-env", "perl-env"],
  proc: ["ps"],
  config: [],
  repo: ["git-remote", "git-log", "git-config"],
  session: [],
  legacy: [],
  links: [],
  routing: [],
};

const FIXED_REFUSALS: Record<string, number> = {
  "relay-token GET /v1/tools": 401,
  "relay-token GET /v1/mcp-servers": 401,
  "relay-token GET /v1/auth/status": 401,
  "relay-token GET /v1/sessions": 401,
  "relay-token POST /v1/auth/login": 401,
  "relay-token POST /v1/query": 401,
  "proxy-token GET /v1/tools": 401,
  "proxy-token GET /v1/mcp-servers": 401,
  "proxy-token GET /v1/auth/status": 401,
  "proxy-token GET /v1/sessions": 401,
  "proxy-token POST /v1/auth/login": 401,
  "proxy-token POST /v1/query": 401,
};

/**
 * Judges the probe's result text (the `Bash` tool result of the route's first step). A route fails on: no report, a
 * marker hit, a required sub-command that did not exit 0, a control that did not hold, or (routing) an attack that was
 * not refused. Names and counts only.
 */
export function verifyRoute(route: RouteId, resultText: string, ctx: RouteContext): RouteVerdict {
  const report = parseReport(resultText);
  if (!report) return { failures: ["no SEC-REPORT line in the tool result"], controls: [], hits: 0, report: null };
  const failures: string[] = [];
  const opened = Array.isArray(report.facts.opened_labels) ? ` (opened: ${(report.facts.opened_labels as string[]).join(", ")})` : "";
  const hits = Object.values(report.hits).reduce((sum, count) => sum + count, 0);
  if (hits > 0) failures.push(`marker hits: ${Object.entries(report.hits).map(([name, count]) => `${name}x${count}`).join(", ")}`);
  for (const name of MUST_SUCCEED[route]) if (report.rc[name] !== 0) failures.push(`sub-command ${name} exited ${report.rc[name] ?? "never ran"}`);
  const held: string[] = [];
  for (const [name, ok] of Object.entries(report.controls)) {
    if (ok) held.push(name);
    else if (route !== "routing" || ctx.phase !== "replay" || name === "earlier_run_saved_its_urls") failures.push(`control did not hold: ${name}${opened}`);
  }
  if (route === "routing") {
    const cases = (report.facts.cases ?? {}) as Record<string, number>;
    if (ctx.phase === "replay") {
      const oldRelay = cases["old-relay-url"];
      if (oldRelay !== 404 && oldRelay !== 401 && !(ctx.afterRestart === true && oldRelay === 0)) failures.push(`old relay URL answered ${oldRelay}`);
      if (cases["old-proxy-token-model-proxy"] !== 401) failures.push(`old proxy token on the model proxy answered ${cases["old-proxy-token-model-proxy"]}`);
      for (const [label, status] of Object.entries(cases)) if (label.startsWith("old-proxy-token GET") && status !== 401) failures.push(`${label} answered ${status}`);
    } else {
      for (const [label, status] of Object.entries(FIXED_REFUSALS)) if (cases[label] !== status) failures.push(`${label} answered ${cases[label] ?? "nothing"}`);
      for (const label of ["ungranted", "unparsable", "batch", "methodless", "resources"]) {
        if (!String(report.facts[`body_${label}`] ?? "").includes("TOOL_DENIED")) failures.push(`hostile relay message ${label} was not answered with the fixed TOOL_DENIED refusal`);
      }
    }
  }
  return { failures, controls: held, hits, report };
}

/** The route context of a rig's current gateway process (host paths, port and canary). */
export function routeContext(rig: SecurityRig, phase?: "probe" | "replay"): RouteContext {
  return {
    markers: rig.markers,
    host: { workspace: rig.gateway.dirs.workspace, home: rig.gateway.dirs.home, persist: rig.gateway.dirs.persist },
    gatewayPort: rig.gateway.port,
    canary: `SYNTH-CANARY-${rig.markers.seed}`,
    phase,
  };
}

export interface RouteTurn {
  phase: "probe" | "replay";
  turn: TurnObservation;
  verdict: RouteVerdict;
  /** Everything wrong with the turn: its stream, runtime, egress, request-scoped credentials and the route's own verdict. */
  problems: string[];
  /** The tool results after the three credential steps and the probe itself (the route's built-in tool steps), in order. */
  extraResults: { isError: boolean; text: string }[];
}

/** Runs one route probe as an ordinary chat turn with the three request-scoped credentials live. */
export async function routeTurn(rig: SecurityRig, route: RouteId, options: { prompt: string; sessionId: string; phase?: "probe" | "replay"; afterRestart?: boolean; label?: "reqlift" | "diemcrm"; user?: string }): Promise<RouteTurn> {
  const ctx = { ...routeContext(rig, options.phase), afterRestart: options.afterRestart };
  const credentialCount = credentialSteps().length;
  const steps = [...credentialSteps(), ...routeSteps(route, ctx)];
  const turn = await chatTurn(rig, { prompt: options.prompt, sessionId: options.sessionId, steps, label: options.label, user: options.user });
  const verdict = verifyRoute(route, turn.results[credentialCount]?.text ?? "", ctx);
  return { phase: options.phase ?? "probe", turn, verdict, problems: [...turnProblems(turn), ...credentialProblems(rig, turn), ...verdict.failures], extraResults: turn.results.slice(credentialCount + 1) };
}

/** The row ids of the regression suite (`security-regression-process.test.ts`) that the summary requires. */
export function regressionRowIds(): string[] {
  const modes = ["fresh", "resumed", "restarted"];
  return [
    "RP.regression",
    ...modes.flatMap((mode) => ROUTE_IDS.map((route) => `RT.${route}.${mode}`)),
    ...modes.flatMap((mode) => [`NC.chat.${mode}`, `NC.interpreter.${mode}`, `NC.read.${mode}`]),
    "X.gitconfig",
    "X.leftovers",
    "X.extension-writes",
    "X.run-leftovers",
    "X.loader-env",
    "RP.negative-control",
    "RP.negative-control.file-detector",
    "RP.negative-control.loader-env",
  ];
}

/** The row ids of the entry-point suite. */
export function entrypointRowIds(): string[] {
  return ["EP.ordinary", "EP.agent", "EP.skill", "EP.subagent", "EP.mcp-direct", "EP.upload", "EP.denied", "EP.enlarge"];
}

/** The row ids of the registry write-only suite (`security-registry-process.test.ts`, MVP-7936, MVP-7957). */
export function registryRowIds(): string[] {
  return ["RG.read", "RG.write", "RG.refused", "RG.preserve-run", "RG.args-url", "RG.failure-text"];
}

/** The row ids of the failure suite (`security-failure-process.test.ts`). */
export function failureRowIds(): string[] {
  return ["IF.startup-exit", "IF.startup-hang", "IF.policy", "IF.check-tool-unshare", "IF.check-tool-true", "IF.cancel", "IF.restart-term", "IF.restart-kill", "IF.detached-complete", "IF.detached-cancel", "IF.detached-kill", "IF.cred-missing", "IF.cred-refused", "IF.timeout", "IF.unavailable", "IF.legacy"];
}
