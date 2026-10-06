/**
 * Scenario drivers for conversations that belong to an API-key label, not to a person (MVP-8044, DEC-ISO-007), shared
 * by `shared-conversation-process.test.ts` (the Outcome Probe rows S1-S10) and the `AD.*` rows of
 * `security-regression-process.test.ts`. They run on the security rig: the compiled gateway, real bwrap, the real
 * runtime, a scripted model and recording doubles. Every value is a synthetic marker; evidence prints names, booleans
 * and counts only.
 *
 * - `runWriterScenario`: person A starts a conversation and person B, then person C, continue it. B's skills, webhook
 *   identity and credential apply (never A's); C has no credential and gets the fixed no-credential text.
 * - `runReplayScenario`: a relay URL saved in A's run is refused in B's run.
 * - `runOtherLabelScenario`: another app sends the conversation's id and gets its own conversation.
 *
 * A Skill call ends a scripted turn (the runtime follows it with the skill's text, which no longer carries the turn's
 * prompt), so a Skill is always the last step of a turn.
 */
import fs from "node:fs";
import path from "node:path";
import { gatewayRequest, type Cleanup, type SpawnedGateway } from "./git-process-gateway.js";
import type { RecordedMessagesRequest } from "./fake-anthropic-api.js";
import { startOAuthMcpStub, type OAuthMcpStub, type OAuthStubRequest } from "./oauth-mcp-stub.js";
import { chatTurn, emit, splitNeedle, treeText, type Counting, type Ndjson, type SecurityRig, type Surface, type ToolStep, type TurnObservation, runLeftoversText, surfacesOf } from "./security-matrix.js";

export const CREATOR_USER = "anna-a";
export const WRITER_USER = "ben-b";
export const THIRD_USER = "cara-c";
const CREATOR_SLUG = "creator-skill";
const WRITER_SLUG = "writer-skill";

export const PER_USER_SCHEMA = {
  fields: [{ key: "token", label: "Token", type: "password", required: true }],
  outputs: [{ outputKey: "Authorization", target: "headers", template: "Bearer {token}" }],
};

export const RECORD_OK = "RECORD-7667-OK";
export const noCredentialText = (server: string): string => `TOOL_AUTH_UNAVAILABLE: No credential for "${server}" was provided with this request. Ask the user to connect their account; retrying will not help.`;
export const LEGACY_TEXT = "This conversation was started before a gateway security update and cannot be continued safely. Please start a new conversation. Retrying will not help.";
export const BUSY_TEXT = "This conversation is still answering an earlier request. Please wait until it has finished, then try again.";

export const bashStep = (command: string): ToolStep => ({ name: "Bash", input: { command, description: "probe" } });
const peruserCall: ToolStep = { name: "mcp__peruser__get_page", input: { id: "P-1" } };
const hookCall: ToolStep = { name: "mcp__agent-gateway-tools__probe_read", input: {} };
const skillId = (userId: string, slug: string): string => `user-${userId}-skills:${slug}`;

export const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/* ------------------------------------------------------------------ */
/*  Persisted state                                                     */
/* ------------------------------------------------------------------ */

export interface SavedEntry {
  sandboxDirId?: string;
  owner?: { label?: string; userId?: string | null };
  sdkSessionId?: string;
  [key: string]: unknown;
}

interface SavedFile {
  sessions?: Record<string, SavedEntry>;
  sessionsByLabel?: Record<string, Record<string, SavedEntry>>;
  [key: string]: unknown;
}

export function readSessionsFile(gateway: SpawnedGateway): SavedFile {
  return JSON.parse(fs.readFileSync(path.join(gateway.dirs.persist, "sessions.json"), "utf8")) as SavedFile;
}

/** The persisted conversation `id` of API-key label `label`, or undefined. */
export function entryOf(gateway: SpawnedGateway, label: string, id: string): SavedEntry | undefined {
  try {
    return readSessionsFile(gateway).sessionsByLabel?.[label]?.[id];
  } catch {
    return undefined;
  }
}

export const conversationDir = (gateway: SpawnedGateway, sandboxDirId: string): string => path.join(gateway.dirs.home, ".agent-sandbox", "sessions", sandboxDirId);

/** Transcripts, `/work` and home of exactly this label's conversation `id` (not another label's conversation of the same id). */
export function ownConversationText(gateway: SpawnedGateway, label: string, id: string): { text: string; files: number } {
  const dirId = entryOf(gateway, label, id)?.sandboxDirId;
  return dirId ? treeText(conversationDir(gateway, dirId)) : { text: "", files: 0 };
}

/* ------------------------------------------------------------------ */
/*  Turns                                                               */
/* ------------------------------------------------------------------ */

export interface PersonTurn {
  prompt: string;
  session: string;
  /** The request's `user_id`; null sends none. */
  user: string | null;
  steps: ToolStep[];
  label?: "reqlift" | "diemcrm";
  body?: Record<string, unknown>;
}

export interface Observed {
  turn: TurnObservation;
  /** The model double's requests made during the turn (warmups included). */
  requests: RecordedMessagesRequest[];
  /** The tool results of this turn's steps, in order (read from the turn's last request, which repeats earlier turns). */
  results: { isError: boolean; text: string }[];
  events: Ndjson[];
  /** Requests of the upstream double during the turn (every one to its MCP endpoint). */
  upstream: OAuthStubRequest[];
  hooks: Counting["hits"];
  /** The gateway log written during the turn. */
  log: string;
}

/** One turn of a person in a conversation, observed by index windows (turns never overlap here). */
export async function observe(rig: SecurityRig, spec: PersonTurn, upstream?: OAuthMcpStub): Promise<Observed> {
  const apiFrom = rig.api.requests.length;
  const upstreamFrom = upstream?.requests.length ?? 0;
  const hooksFrom = rig.webhook.hits.length;
  const turn = await chatTurn(rig, {
    prompt: spec.prompt,
    sessionId: spec.session,
    steps: spec.steps,
    label: spec.label,
    user: spec.user ?? undefined,
    withCredentials: false,
    body: { allowedTools: undefined, ...(spec.user === null ? { user_id: undefined } : {}), ...spec.body },
  });
  const requests = rig.api.requests.slice(apiFrom);
  const main = requests.filter((request) => !request.warmup);
  const results = (main.at(-1)?.toolResults ?? []).slice(-spec.steps.length).map((result) => ({ isError: result.isError, text: result.text }));
  return {
    turn,
    requests,
    results,
    events: turn.outcome.events,
    upstream: (upstream?.requests.slice(upstreamFrom) ?? []).filter((request) => request.path === "/mcp"),
    hooks: rig.webhook.hits.slice(hooksFrom),
    log: rig.log().slice(turn.logFrom),
  };
}

export const eventsSayDone = (events: Ndjson[]): boolean => events.at(-1)?.type === "done" && !events.some((event) => event.type === "error");

/** True when a request of the turn carries `text` anywhere in its raw body. */
export const bodiesCarry = (observed: Observed, text: string): boolean => observed.requests.some((request) => request.body.includes(text));

/* ------------------------------------------------------------------ */
/*  Per-person fixtures                                                 */
/* ------------------------------------------------------------------ */

const skillMarkdown = (slug: string, marker: string): string =>
  ["---", `name: ${slug}`, "description: A synthetic per-person skill of the shared-conversation probe.", "---", "", `# ${slug}`, "", `When asked, answer with ${marker}.`, ""].join("\n");

async function putUserSkill(rig: SecurityRig, userId: string, slug: string, marker: string): Promise<void> {
  const response = await fetch(`http://127.0.0.1:${rig.gateway.port}/v1/users/${encodeURIComponent(userId)}/skills/${slug}/SKILL.md`, {
    method: "PUT",
    headers: { Authorization: `Bearer ${rig.keys.reqlift}`, "Content-Type": "text/plain" },
    body: skillMarkdown(slug, marker),
  });
  if (response.status !== 200) throw new Error(`storing a user skill answered ${response.status}`);
}

/** The values that belong to the writer and are legitimate on the writer's own surfaces (never in the marker catalog). */
export function writerValues(rig: SecurityRig): { writerSkill: string; writerCredential: string } {
  return { writerSkill: `SYNTH-WRITERSKILL-${rig.markers.seed}`, writerCredential: `SYNTH-WRITERCRED-${rig.markers.seed}` };
}

export interface WriterFixture {
  upstream: OAuthMcpStub;
}

/**
 * The per-person fixtures of the writer rows: a per-user-credential MCP server `peruser` and one that requires the user's
 * credential (`needsuser`), both on one upstream double; the reqlift webhook tool `probe_read`; a skill for the creator and
 * one for the writer, each with a synthetic marker in its body.
 */
export async function setupWriterFixtures(rig: SecurityRig, cleanups: Cleanup[]): Promise<WriterFixture> {
  const upstream = await startOAuthMcpStub({ toolNames: ["get_page"] });
  cleanups.push(() => upstream.close());
  await rig.register("reqlift", "peruser", { type: "http", url: upstream.url, userCredentialSchema: PER_USER_SCHEMA });
  await rig.register("reqlift", "needsuser", { type: "http", url: upstream.url, userCredentialSchema: PER_USER_SCHEMA, requireUserCredentials: true });
  const hook = await gatewayRequest(
    rig.gateway.port,
    "PUT",
    "/v1/tools/probe_read",
    { description: "probe", input_schema: { type: "object", properties: {} }, webhook_url: `${rig.webhook.base}/probe_read` },
    rig.keys.reqlift,
  );
  if (hook.status >= 300) throw new Error(`registering the webhook tool answered ${hook.status}`);
  await putUserSkill(rig, CREATOR_USER, CREATOR_SLUG, rig.markers.values.creatorSkill);
  await putUserSkill(rig, WRITER_USER, WRITER_SLUG, writerValues(rig).writerSkill);
  await sleep(300);
  return { upstream };
}

/* ------------------------------------------------------------------ */
/*  The writer scenario (S7, S8, S9, AD.same-label-writer)              */
/* ------------------------------------------------------------------ */

export interface WriterScenario {
  session: string;
  creator: Observed;
  writer: Observed;
  replay: Observed;
  third: Observed;
  tag: string;
}

/** Counts, inside the sandbox, the files below the run's skill bundles that carry `value` (the needle never appears whole in the command). */
function bundleProbe(creatorSkill: string, writerSkill: string): string {
  const count = (value: string): string => {
    const [first, second] = splitNeedle(value);
    return `$( [ -n "$DIRS" ] && grep -rl '${first}''${second}' $DIRS 2>/dev/null | wc -l || echo 0 )`;
  };
  return [
    "cat /work/shared.txt",
    "DIRS=$(find / -path /proc -prune -o -type d -name 'agw-userskills-*' -print 2>/dev/null)",
    'echo BUNDLES=$(echo "$DIRS" | grep -c .)',
    `echo CREATOR_SKILL_IN_BUNDLE=${count(creatorSkill)}`,
    `echo WRITER_SKILL_IN_BUNDLE=${count(writerSkill)}`,
  ].join("; ");
}

/**
 * A (creator) starts the conversation with A's credential, A's webhook identity and a file; B continues it with B's own
 * credential and skill (a Skill call to B's skill is the last step); B then calls A's skill, which must fail; C continues it
 * with no credential. The creator's turn does not invoke its skill: whatever a writer's turn adds to a shared conversation
 * stays in it, so the checks read only what is per run (see `writerProblems`).
 */
export async function runWriterScenario(rig: SecurityRig, fixture: WriterFixture, tag: string): Promise<WriterScenario> {
  const v = rig.markers.values;
  const own = writerValues(rig);
  const session = `${tag}-conv`;
  const override = (credential: string): Record<string, unknown> => ({ mcpCredentialOverrides: { peruser: { headers: { Authorization: `Bearer ${credential}` } } } });
  const creator = await observe(rig, { prompt: `${tag}-1`, session, user: CREATOR_USER, steps: [peruserCall, hookCall, bashStep("echo CREATOR-WORK-FILE > /work/shared.txt; echo wrote")], body: override(v.creatorCredential) }, fixture.upstream);
  const writer = await observe(
    rig,
    { prompt: `${tag}-2`, session, user: WRITER_USER, steps: [peruserCall, hookCall, bashStep(bundleProbe(v.creatorSkill, own.writerSkill)), { name: "Skill", input: { skill: skillId(WRITER_USER, WRITER_SLUG) } }], body: override(own.writerCredential) },
    fixture.upstream,
  );
  const replay = await observe(rig, { prompt: `${tag}-3`, session, user: WRITER_USER, steps: [{ name: "Skill", input: { skill: skillId(CREATOR_USER, CREATOR_SLUG) } }] }, fixture.upstream);
  const third = await observe(rig, { prompt: `${tag}-4`, session, user: THIRD_USER, steps: [peruserCall, { name: "mcp__needsuser__get_page", input: { id: "P-1" } }] }, fixture.upstream);
  return { session, creator, writer, replay, third, tag };
}

export interface ScenarioVerdict {
  /** S7: the writer's skills and webhook identity. */
  skills: string[];
  /** S8: the writer's credential. */
  credentials: string[];
  /** S9: a writer without a credential. */
  noCredential: string[];
  /** Everything else (streams, the shared home). */
  general: string[];
  controls: string[];
}

const authorizationsOf = (observed: Observed): (string | undefined)[] => observed.upstream.map((request) => request.headers.authorization);
const hookUsers = (observed: Observed): string[] => observed.hooks.map((hit) => String((JSON.parse(hit.context ?? "{}") as { user_id?: unknown }).user_id ?? "none"));

export function writerProblems(rig: SecurityRig, scenario: WriterScenario): ScenarioVerdict {
  const v = rig.markers.values;
  const own = writerValues(rig);
  const { creator, writer, replay, third } = scenario;
  const verdict: ScenarioVerdict = { skills: [], credentials: [], noCredential: [], general: [], controls: [] };
  const creatorBearer = `Bearer ${v.creatorCredential}`;
  const writerBearer = `Bearer ${own.writerCredential}`;
  const loaded = (observed: Observed): { skills?: string[]; user_id?: string | null } | undefined => observed.events.find((event) => event.type === "skills_loaded") as { skills?: string[]; user_id?: string | null } | undefined;

  for (const [name, observed] of [["creator", creator], ["writer", writer], ["replay", replay], ["third", third]] as const) {
    if (!eventsSayDone(observed.events)) verdict.general.push(`the ${name} turn did not end in done without an error event`);
  }
  if (!writer.results[2]?.text.includes("CREATOR-WORK-FILE")) verdict.general.push("the writer's run did not find the creator's file in the shared work area");
  else verdict.controls.push("writer_read_the_creators_file_in_the_shared_home");

  // S8, first the live control: the creator's own credential reached the upstream in the creator's turn.
  const creatorAuth = authorizationsOf(creator);
  if (creatorAuth.length > 0 && creatorAuth.every((value) => value === creatorBearer) && creator.upstream.some((request) => request.rpcMethods.includes("tools/call"))) verdict.controls.push("creator_credential_recorded_at_the_upstream_in_the_creator_turn");
  else verdict.credentials.push("the upstream did not record exactly the creator's credential for the creator's call (the control is not live)");
  const writerAuth = authorizationsOf(writer);
  if (writerAuth.length > 0 && writerAuth.every((value) => value === writerBearer) && writer.upstream.some((request) => request.rpcMethods.includes("tools/call"))) verdict.controls.push("writer_credential_and_only_it_recorded_at_the_upstream_in_the_writer_turn");
  else verdict.credentials.push(`the upstream did not record exactly the writer's credential for the writer's call (${writerAuth.length} requests, ${writerAuth.filter((value) => value === creatorBearer).length} with the creator's credential)`);
  if (!writer.results[0] || writer.results[0].isError || !writer.results[0].text.includes(RECORD_OK)) verdict.credentials.push("the writer's call to the per-user server did not answer");

  // S7: the webhook identity and the writer's skills, on per-run surfaces only.
  const creatorHooks = hookUsers(creator);
  if (creatorHooks.length === 1 && creatorHooks[0] === CREATOR_USER) verdict.controls.push("creator_webhook_identity_recorded_in_the_creator_turn");
  else verdict.skills.push("the webhook double did not record exactly the creator's user id in the creator's turn (the control is not live)");
  const writerHooks = hookUsers(writer);
  if (writerHooks.length === 1 && writerHooks[0] === WRITER_USER) verdict.controls.push("writer_webhook_identity_recorded_in_the_writer_turn");
  else verdict.skills.push("the webhook context did not carry the writer's user id");
  const writerLoaded = loaded(writer);
  if (writerLoaded?.user_id === WRITER_USER && writerLoaded.skills?.includes(skillId(WRITER_USER, WRITER_SLUG)) && !writerLoaded.skills.includes(skillId(CREATOR_USER, CREATOR_SLUG))) verdict.controls.push("skills_loaded_lists_the_writers_skill_and_not_the_creators");
  else verdict.skills.push("skills_loaded did not list exactly the writer's skill for the writer");
  const bundleText = writer.results[2]?.text ?? "";
  if (/BUNDLES=1\b/.test(bundleText) && /WRITER_SKILL_IN_BUNDLE=1\b/.test(bundleText) && /CREATOR_SKILL_IN_BUNDLE=0\b/.test(bundleText)) verdict.controls.push("the_bundle_mounted_in_the_writer_run_holds_the_writers_skill_only");
  else verdict.skills.push("the skill bundle mounted in the writer's run did not hold the writer's skill only");
  if (writer.results[3] && !writer.results[3].isError && bodiesCarry(writer, own.writerSkill)) verdict.controls.push("writer_skill_invoked_and_its_text_reached_the_model");
  else verdict.skills.push("the writer's own skill could not be invoked in the writer's run");
  if (bodiesCarry(writer, v.creatorSkill)) verdict.skills.push("the creator's skill text reached the model in the writer's run");
  if (replay.results[0]?.isError === true && !bodiesCarry(replay, v.creatorSkill)) verdict.controls.push("call_to_the_creators_skill_failed_in_the_writers_run");
  else verdict.skills.push("a call to the creator's skill did not fail in the writer's run");

  // S9: no credential, no creator fallback.
  if (third.results[0]?.isError === true && third.results[0].text === noCredentialText("peruser")) verdict.controls.push("exact_no_credential_text");
  else verdict.noCredential.push("the call without a credential did not get the fixed no-credential text");
  if (third.upstream.some((request) => request.rpcMethods.includes("tools/call"))) verdict.noCredential.push("a tools/call reached the upstream in a run without a credential");
  if (authorizationsOf(third).some((value) => value === creatorBearer || value === writerBearer)) verdict.noCredential.push("a credential of an earlier writer reached the upstream in a run without a credential");
  else verdict.controls.push("no_credential_of_an_earlier_person_reached_the_upstream_in_the_credential_less_run");
  if (third.results[1]?.isError === true && third.results[1].text.includes("No such tool available") && /mcp\.server\.omitted serverName=needsuser reason=missing_user_credential/.test(third.log)) verdict.controls.push("required_credential_server_left_out_and_call_refused");
  else verdict.noCredential.push("the server that requires the user's credential was not left out of the credential-less run");
  return verdict;
}

export const verdictProblems = (verdict: ScenarioVerdict): string[] => [...verdict.general, ...verdict.skills, ...verdict.credentials, ...verdict.noCredential];

/** The surfaces of a scenario's turns, with the transcripts of the one shared conversation. */
export function scenarioSurfaces(rig: SecurityRig, observed: Observed[]): Surface[] {
  return surfacesOf(rig, observed.map((entry) => entry.turn));
}

/* ------------------------------------------------------------------ */
/*  The relay replay scenario (AD.relay-token-replay)                   */
/* ------------------------------------------------------------------ */

const RELAY_FACTS = String.raw`python3 - <<'PY'
import json, os, re
pattern = re.compile(rb'http://127\.0\.0\.1:\d+/mcp/[A-Za-z0-9_-]+')
urls = []
me = str(os.getpid())
def add(data):
    for m in pattern.finditer(data):
        u = m.group(0).decode()
        if u not in urls:
            urls.append(u)
for pid in os.listdir('/proc'):
    if not pid.isdigit() or pid == me:
        continue
    for name in ('cmdline', 'environ'):
        try:
            add(open('/proc/%s/%s' % (pid, name), 'rb').read())
        except Exception:
            continue
for root in ('/tmp', '/home/node'):
    for dirpath, dirs, files in os.walk(root):
        for f in files:
            try:
                p = os.path.join(dirpath, f)
                if os.path.getsize(p) > 5000000:
                    continue
                add(open(p, 'rb').read())
            except Exception:
                continue
json.dump({'relay': urls}, open('/work/replay.json', 'w'))
PY`;

/**
 * Calls every saved relay URL from inside the sandbox with `tools/list` (and, with `withCall`, `tools/call`) and prints
 * `<label>_STATUS=<codes> URLS=<n>`.
 */
const relayCalls = (label: string, withCall: boolean): string => String.raw`python3 - <<'PY'
import json, urllib.request, urllib.error
facts = json.load(open('/work/replay.json'))
codes = []
bodies = [{'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list', 'params': {}}]
if ${withCall ? "True" : "False"}:
    bodies.append({'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call', 'params': {'name': 'get_page', 'arguments': {'id': 'P-9'}}})
for u in facts['relay']:
    for body in bodies:
        req = urllib.request.Request(u, data=json.dumps(body).encode(), headers={'content-type': 'application/json'}, method='POST')
        try:
            codes.append(str(urllib.request.urlopen(req, timeout=10).status))
        except urllib.error.HTTPError as e:
            codes.append(str(e.code))
        except Exception:
            codes.append('error')
print('${label}_STATUS=' + ','.join(codes) + ' URLS=' + str(len(facts['relay'])))
PY`;

export interface ReplayScenario {
  creator: Observed;
  writer: Observed;
}

/** A's run saves its relay URLs and calls them while it lives (the control); B's run calls the saved URLs. */
export async function runReplayScenario(rig: SecurityRig, fixture: WriterFixture, tag: string): Promise<ReplayScenario> {
  const v = rig.markers.values;
  const own = writerValues(rig);
  const session = `${tag}-conv`;
  const override = (credential: string): Record<string, unknown> => ({ mcpCredentialOverrides: { peruser: { headers: { Authorization: `Bearer ${credential}` } } } });
  const creator = await observe(rig, { prompt: `${tag}-1`, session, user: CREATOR_USER, steps: [peruserCall, bashStep([RELAY_FACTS, relayCalls("LIVE", false)].join("\n"))], body: override(v.creatorCredential) }, fixture.upstream);
  const writer = await observe(rig, { prompt: `${tag}-2`, session, user: WRITER_USER, steps: [bashStep(relayCalls("REPLAY", true))], body: override(own.writerCredential) }, fixture.upstream);
  return { creator, writer };
}

export function replayProblems(rig: SecurityRig, scenario: ReplayScenario): { problems: string[]; controls: string[] } {
  const v = rig.markers.values;
  const problems: string[] = [];
  const controls: string[] = [];
  const { creator, writer } = scenario;
  for (const [name, observed] of [["creator", creator], ["writer", writer]] as const) if (!eventsSayDone(observed.events)) problems.push(`the ${name} turn did not end in done without an error event`);
  const live = /LIVE_STATUS=([0-9a-z,]*) URLS=(\d+)/.exec(creator.results[1]?.text ?? "");
  const urls = Number(live?.[2] ?? 0);
  if (live && urls > 0 && live[1].split(",").every((code) => code === "200")) controls.push("saved_relay_url_answered_200_to_tools_list_inside_the_creator_run");
  else problems.push("the saved relay URL did not answer 200 inside the creator's own run (the replay control is not live)");
  const replay = /REPLAY_STATUS=([0-9a-z,]*) URLS=(\d+)/.exec(writer.results[0]?.text ?? "");
  if (replay && Number(replay[2]) === urls && urls > 0 && replay[1].split(",").length === urls * 2 && replay[1].split(",").every((code) => code === "404")) controls.push("saved_relay_url_refused_404_in_the_writer_run");
  else problems.push("the creator's saved relay URL was not refused with 404 for every call in the writer's run");
  if (writer.upstream.some((request) => request.rpcMethods.includes("tools/call"))) problems.push("a tools/call reached the upstream during the writer's replay");
  if (authorizationsOf(writer).some((value) => value === `Bearer ${v.creatorCredential}`)) problems.push("the creator's credential reached the upstream during the writer's run");
  else controls.push("upstream_recorded_no_tools_call_and_no_creator_credential_during_the_writer_run");
  return { problems, controls };
}

/* ------------------------------------------------------------------ */
/*  The other-label scenario (S5, AD.other-label)                       */
/* ------------------------------------------------------------------ */

export interface OtherLabelScenario {
  session: string;
  creator: Observed;
  other: Observed;
  creatorAgain: Observed;
  tag: string;
}

/** Another app sends the conversation's id: it gets its own conversation. The creator's conversation is untouched. */
export async function runOtherLabelScenario(rig: SecurityRig, tag: string): Promise<OtherLabelScenario> {
  const v = rig.markers.values;
  const [first, second] = splitNeedle(v.sessionBFile);
  const session = `${tag}-conv`;
  const creator = await observe(rig, { prompt: `${tag}-1 ${v.sessionBTurn}`, session, user: CREATOR_USER, steps: [bashStep(`echo ${v.sessionBFile} > /work/c-owned.txt; echo wrote`)] });
  const other = await observe(rig, { prompt: `${tag}-2`, session, user: CREATOR_USER, label: "diemcrm", steps: [bashStep("echo FILES=$(ls -A /work | wc -l); echo SEEN=$(cat /work/c-owned.txt 2>&1 | head -c 200)")] });
  const creatorAgain = await observe(rig, { prompt: `${tag}-3`, session, user: WRITER_USER, steps: [bashStep(`echo OWN=$(grep -c '${first}''${second}' /work/c-owned.txt)`)] });
  return { session, creator, other, creatorAgain, tag };
}

export function otherLabelProblems(rig: SecurityRig, scenario: OtherLabelScenario): { problems: string[]; controls: string[]; evidence: Record<string, boolean> } {
  const problems: string[] = [];
  const controls: string[] = [];
  const { session, creator, other, creatorAgain, tag } = scenario;
  const creatorEntry = entryOf(rig.gateway, "reqlift", session);
  const ownEntry = entryOf(rig.gateway, "diemcrm", session);
  const promptInRequest = other.requests.some((request) => request.userTexts.some((text) => text.includes(`${tag}-1`)));
  const evidence = {
    other_label_resumed_creator_conversation: ownEntry === undefined || promptInRequest,
    creator_prompt_in_other_label_request: promptInRequest,
    other_label_has_own_entry: ownEntry !== undefined,
    other_label_shares_creator_home: ownEntry !== undefined && creatorEntry !== undefined && ownEntry.sandboxDirId === creatorEntry.sandboxDirId,
  };
  for (const [name, observed] of [["creator", creator], ["other-label", other], ["creator-again", creatorAgain]] as const) if (!eventsSayDone(observed.events)) problems.push(`the ${name} turn did not end in done without an error event`);
  if (!creatorEntry?.sandboxDirId) problems.push("the creator's conversation has no recorded home");
  if (!ownEntry?.sandboxDirId) problems.push("the other label did not get a conversation of its own");
  if (evidence.other_label_resumed_creator_conversation) problems.push("the other label resumed the creator's conversation");
  if (evidence.other_label_shares_creator_home) problems.push("the other label runs in the creator's home");
  if (/FILES=0\b/.test(other.results[0]?.text ?? "")) controls.push("other_label_work_area_is_empty");
  else problems.push("the other label's work area was not empty");
  if (/OWN=1\b/.test(creatorAgain.results[0]?.text ?? "")) controls.push("creator_conversation_intact_and_continued_by_another_person_of_its_label");
  else problems.push("the creator's file is not in the creator's conversation (the control is not live)");
  if (creatorEntry?.sandboxDirId && ownEntry?.sandboxDirId && creatorEntry.sandboxDirId !== ownEntry.sandboxDirId) controls.push("the_two_labels_have_different_homes");
  return { problems, controls, evidence };
}

/** The surfaces of the other label's turn; its transcripts are its own conversation's, not the creator's of the same id. */
export function otherLabelSurfaces(rig: SecurityRig, scenario: OtherLabelScenario): Surface[] {
  const base = surfacesOf(rig, [scenario.other.turn]);
  const own = ownConversationText(rig.gateway, "diemcrm", scenario.session);
  return base.map((surface) => (surface.name === "transcripts" ? { name: "transcripts", text: `${own.text}\n${runLeftoversText(rig.gateway).text}` } : surface));
}

/** Names and booleans only. */
export function emitEvidence(row: string, fields: Record<string, boolean | number | string>): void {
  emit(`SHARED-CONVERSATION-EVIDENCE ${Object.entries({ row, ...fields }).map(([key, value]) => `${key}=${String(value)}`).join(" ")}`);
}
