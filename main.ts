// github-core-clone-01 — a GitHub-compatible git forge in one file.
// Node 22, standard library only, no git binary, no external service.
// Surfaces: git smart HTTP (upload-pack v2 / receive-pack v0), REST v3,
// GraphQL v4, MCP (Streamable HTTP). In-memory store, deterministic state.
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { createHash } from 'node:crypto';
import { deflateSync, inflateSync } from 'node:zlib';
import { Buffer } from 'node:buffer';

// ---------------------------------------------------------------- constants
const VERSION = '1.0.0';
const AGENT = 'forge/1.0.0';
const VIEWER_LOGIN = 'adaiversen';
const VIEWER_ID = 1000;
const VIEWER_NAME = 'ada iversen';
const VIEWER_EMAIL = 'adaiversen@example.invalid';
const DEFAULT_BRANCH = 'main';
const FIXED_DATE = '2025-01-01T00:00:00Z';
const COMMIT_TS = 1700000000; // fixed, deterministic commit timestamps
const ZERO_OID = '0000000000000000000000000000000000000000';
const LABEL_SEED = ['bug', 'enhancement', 'documentation', 'question', 'good first issue', 'help wanted'];

// ---------------------------------------------------------------- crypto utils
function sha1(data: Buffer): string {
  return createHash('sha1').update(data).digest('hex');
}
function isOid(s: string): boolean {
  return /^[0-9a-f]{40}$/.test(s);
}
function b64encode(s: string): string {
  return Buffer.from(s, 'utf8').toString('base64');
}
function b64decode(s: string): string {
  return Buffer.from(s, 'base64').toString('utf8');
}

// ---------------------------------------------------------------- pkt-lines
function pktLine(payload: Buffer | string): Buffer {
  const data = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const len = data.length + 4;
  // Single allocation: header + payload in one buffer (hot path: advertisements,
  // ls-refs, fetch responses and push reports all frame through here).
  const out = Buffer.allocUnsafe(len);
  out.write(len.toString(16).padStart(4, '0'), 0, 4, 'ascii');
  data.copy(out, 4);
  return out;
}
const FLUSH = Buffer.from('0000', 'ascii');
const DELIM = Buffer.from('0001', 'ascii');
const EMPTY_BODY = Buffer.alloc(0);
const EMPTY_PARAMS = new URLSearchParams();

interface PktPacket {
  kind: 'data' | 'flush' | 'delim' | 'end';
  data?: Buffer;
}
// Parse pkt-lines from a buffer starting at offset. Returns packets + new offset.
function parsePktLines(buf: Buffer, start: number): { packets: PktPacket[]; offset: number } {
  const packets: PktPacket[] = [];
  let off = start;
  while (off + 4 <= buf.length) {
    const len = parseInt(buf.toString('ascii', off, off + 4), 16);
    if (Number.isNaN(len)) break;
    if (len === 0) {
      packets.push({ kind: 'flush' });
      off += 4;
      continue;
    }
    if (len === 1) {
      packets.push({ kind: 'delim' });
      off += 4;
      continue;
    }
    if (len === 2) {
      packets.push({ kind: 'end' });
      off += 4;
      continue;
    }
    if (off + len > buf.length) break;
    packets.push({ kind: 'data', data: buf.subarray(off + 4, off + len) });
    off += len;
  }
  return { packets, offset: off };
}

// ---------------------------------------------------------------- git objects
type ObjType = 'commit' | 'tree' | 'blob' | 'tag';
interface GitObject {
  type: ObjType;
  data: Buffer;
}
function hashObject(type: ObjType, data: Buffer): string {
  const header = Buffer.from(`${type} ${data.length}\0`, 'utf8');
  return sha1(Buffer.concat([header, data]));
}
interface CommitInfo {
  tree: string;
  parents: string[];
  message: string;
  author: string;
  committer: string;
}
function parseCommit(data: Buffer): CommitInfo {
  const text = data.toString('utf8');
  const headEnd = text.indexOf('\n\n');
  const head = headEnd >= 0 ? text.slice(0, headEnd) : text;
  const message = headEnd >= 0 ? text.slice(headEnd + 2) : '';
  const info: CommitInfo = { tree: '', parents: [], message, author: '', committer: '' };
  for (const line of head.split('\n')) {
    if (line.startsWith('tree ')) info.tree = line.slice(5).trim();
    else if (line.startsWith('parent ')) info.parents.push(line.slice(7).trim());
    else if (line.startsWith('author ')) info.author = line.slice(7);
    else if (line.startsWith('committer ')) info.committer = line.slice(10);
  }
  return info;
}
function buildCommit(tree: string, parents: string[], message: string): { oid: string; data: Buffer } {
  const msg = message.endsWith('\n') ? message : message + '\n';
  const ident = `${VIEWER_NAME} <${VIEWER_EMAIL}> ${COMMIT_TS} +0000`;
  let text = `tree ${tree}\n`;
  for (const p of parents) text += `parent ${p}\n`;
  text += `author ${ident}\ncommitter ${ident}\n\n${msg}`;
  const data = Buffer.from(text, 'utf8');
  return { oid: hashObject('commit', data), data };
}
interface TreeEntry {
  mode: string;
  name: string;
  oid: string;
}
function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let off = 0;
  while (off < data.length) {
    const sp = data.indexOf(0x20, off);
    if (sp < 0) break;
    const mode = data.toString('ascii', off, sp);
    const nul = data.indexOf(0x00, sp);
    if (nul < 0) break;
    const name = data.toString('utf8', sp + 1, nul);
    const oid = data.subarray(nul + 1, nul + 21).toString('hex');
    entries.push({ mode, name, oid });
    off = nul + 21;
  }
  return entries;
}
function buildTree(entries: TreeEntry[]): { oid: string; data: Buffer } {
  const sorted = [...entries].sort((a, b) => {
    const an = a.mode === '40000' ? a.name + '/' : a.name;
    const bn = b.mode === '40000' ? b.name + '/' : b.name;
    return an < bn ? -1 : an > bn ? 1 : 0;
  });
  const parts: Buffer[] = [];
  for (const e of sorted) {
    parts.push(Buffer.from(`${e.mode} ${e.name}\0`, 'utf8'));
    parts.push(Buffer.from(e.oid, 'hex'));
  }
  const data = Buffer.concat(parts);
  return { oid: hashObject('tree', data), data };
}
interface TagInfo {
  object: string;
  type: string;
  tag: string;
  message: string;
}
function parseTag(data: Buffer): TagInfo {
  const text = data.toString('utf8');
  const headEnd = text.indexOf('\n\n');
  const head = headEnd >= 0 ? text.slice(0, headEnd) : text;
  const info: TagInfo = { object: '', type: '', tag: '', message: headEnd >= 0 ? text.slice(headEnd + 2) : '' };
  for (const line of head.split('\n')) {
    if (line.startsWith('object ')) info.object = line.slice(7).trim();
    else if (line.startsWith('type ')) info.type = line.slice(5).trim();
    else if (line.startsWith('tag ')) info.tag = line.slice(4).trim();
  }
  return info;
}
function storeBlob(repo: Repo, content: Buffer): string {
  const oid = hashObject('blob', content);
  repo.objects.set(oid, { type: 'blob', data: content });
  return oid;
}

// ---------------------------------------------------------------- pack format
// Encoded pack bytes (type/size header + deflated payload) per stored object.
// Objects are immutable once stored (oid = content hash), so the encoding never
// goes stale; keyed by object identity, which is stable for repo-stored objects.
// Repeated clones of the same history deflate each object once, not once per clone.
const packObjectCache = new WeakMap<GitObject, Buffer>();
function writePack(objects: GitObject[]): Buffer {
  const parts: Buffer[] = [];
  const header = Buffer.alloc(12);
  header.write('PACK', 0, 'ascii');
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(objects.length, 8);
  parts.push(header);
  for (const obj of objects) {
    let encoded = packObjectCache.get(obj);
    if (encoded === undefined) {
      const typeNum = obj.type === 'commit' ? 1 : obj.type === 'tree' ? 2 : obj.type === 'blob' ? 3 : 4;
      const size = obj.data.length;
      const bytes: number[] = [];
      let first = (typeNum << 4) | (size & 0x0f);
      let remaining = size >>> 4;
      if (remaining > 0) first |= 0x80;
      bytes.push(first);
      while (remaining > 0) {
        let b = remaining & 0x7f;
        remaining >>>= 7;
        if (remaining > 0) b |= 0x80;
        bytes.push(b);
      }
      encoded = Buffer.concat([Buffer.from(bytes), deflateSync(obj.data)]);
      packObjectCache.set(obj, encoded);
    }
    parts.push(encoded);
  }
  const body = Buffer.concat(parts);
  const trailer = createHash('sha1').update(body).digest();
  return Buffer.concat([body, trailer]);
}
interface ParsedPack {
  objects: GitObject[];
  ok: boolean;
}
function readPack(buf: Buffer): ParsedPack {
  const out: ParsedPack = { objects: [], ok: false };
  try {
    if (buf.length < 32) return out;
    if (buf.toString('ascii', 0, 4) !== 'PACK') return out;
    const version = buf.readUInt32BE(4);
    if (version !== 2) return out;
    const count = buf.readUInt32BE(8);
    let off = 12;
    for (let i = 0; i < count; i++) {
      if (off >= buf.length) return out;
      let byte = buf[off++];
      const typeNum = (byte >> 4) & 0x07;
      let size = byte & 0x0f;
      let shift = 4;
      while (byte & 0x80) {
        if (off >= buf.length) return out;
        byte = buf[off++];
        size |= (byte & 0x7f) << shift;
        shift += 7;
      }
      const type: ObjType = typeNum === 1 ? 'commit' : typeNum === 2 ? 'tree' : typeNum === 3 ? 'blob' : typeNum === 4 ? 'tag' : 'blob';
      if (typeNum === 6) {
        // OFS_DELTA: not expected from the suite client; skip by failing.
        return out;
      }
      if (typeNum === 7) {
        // REF_DELTA: not expected from the suite client.
        return out;
      }
      // Single-pass inflate: one native call, exact consumed length.
      const one = inflateOne(buf, off);
      if (one === null) return out;
      out.objects.push({ type, data: one.data });
      off = one.next;
      void size;
    }
    out.ok = true;
    return out;
  } catch {
    return out;
  }
}
// Inflate exactly one zlib stream starting at `off` and report how many input
// bytes it consumed. `inflateSync` with `info: true` returns the engine, whose
// `bytesWritten` is the input consumed (the stream stops at its own end, so the
// bytes of the next object — or the pack trailer — are left untouched). One
// native call per object instead of a binary search of trial inflates.
// Falls back to the old binary search when the engine does not report it.
function inflateOne(buf: Buffer, off: number): { data: Buffer; next: number } | null {
  try {
    const r = inflateSync(buf.subarray(off), { info: true }) as unknown as {
      buffer: Buffer;
      engine?: { bytesWritten?: unknown };
    };
    const consumed = r.engine?.bytesWritten;
    if (typeof consumed === 'number' && Number.isInteger(consumed) && consumed > 0 && off + consumed <= buf.length) {
      return { data: r.buffer, next: off + consumed };
    }
  } catch {
    // Fall through to the binary-search length probe below.
  }
  try {
    const len = compressedLength(buf, off);
    return { data: inflateSync(buf.subarray(off, off + len)), next: off + len };
  } catch {
    return null;
  }
}
function compressedLength(buf: Buffer, off: number): number {
  let lo = 1;
  let hi = buf.length - off;
  // find the smallest length that inflates cleanly to a complete stream
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    try {
      inflateSync(buf.subarray(off, off + mid));
      hi = mid;
    } catch {
      lo = mid + 1;
    }
  }
  return lo;
}

// ---------------------------------------------------------------- store model
interface Label {
  name: string;
  color: string;
  description: string;
}
interface Issue {
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: string[];
  seq: number;
  user: string;
}
interface IssueComment {
  id: number;
  body: string;
  user: string;
}
interface Pull {
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  merged: boolean;
  mergedAt: string | null;
  mergeCommitSha: string | null;
  headRef: string;
  headSha: string;
  baseRef: string;
  baseSha: string;
  seq: number;
}
interface Repo {
  id: number;
  owner: string;
  name: string;
  description: string;
  isPrivate: boolean;
  defaultBranch: string;
  objects: Map<string, GitObject>;
  refs: Map<string, string>;
  issues: Issue[];
  nextIssue: number;
  labels: Map<string, Label>;
  pulls: Pull[];
  nextPull: number;
  comments: Map<number, IssueComment[]>;
  nextCommentId: number;
  seq: number;
  viewVersion: number;
  commitCache: Map<string, CommitInfo>;
  treeCache: Map<string, TreeEntry[]>;
}
interface Store {
  repos: Map<string, Repo>;
  nextRepoId: number;
  nextIssueId: number;
  nextPullId: number;
  seq: number;
}
const store: Store = { repos: new Map(), nextRepoId: 1, nextIssueId: 1, nextPullId: 1, seq: 0 };

function fullName(owner: string, name: string): string {
  return `${owner}/${name}`;
}
function getRepo(owner: string, name: string): Repo | undefined {
  return store.repos.get(fullName(owner, name));
}
function getRepoById(id: number): Repo | undefined {
  for (const r of store.repos.values()) if (r.id === id) return r;
  return undefined;
}
function createRepo(owner: string, name: string, description: string, isPrivate: boolean): Repo {
  const repo: Repo = {
    id: store.nextRepoId++,
    owner,
    name,
    description,
    isPrivate,
    defaultBranch: DEFAULT_BRANCH,
    objects: new Map(),
    refs: new Map(),
    issues: [],
    nextIssue: 1,
    labels: new Map(),
    pulls: [],
    nextPull: 1,
    comments: new Map(),
    nextCommentId: 1,
    seq: ++store.seq,
    viewVersion: 0,
    commitCache: new Map(),
    treeCache: new Map(),
  };
  for (const label of LABEL_SEED) {
    repo.labels.set(label, { name: label, color: '000000', description: '' });
  }
  store.repos.set(fullName(owner, name), repo);
  return repo;
}
function deleteRepo(owner: string, name: string): boolean {
  return store.repos.delete(fullName(owner, name));
}
function viewerRepos(): Repo[] {
  const out: Repo[] = [];
  for (const r of store.repos.values()) if (r.owner === VIEWER_LOGIN) out.push(r);
  out.sort((a, b) => a.seq - b.seq);
  return out;
}

// Global ids: opaque, stable, never equal to the numeric database id.
function repoGlobalId(repo: Repo): string {
  return b64encode(`repo:${repo.id}`);
}
function issueGlobalId(repo: Repo, issue: Issue): string {
  return b64encode(`issue:${repo.id}:${issue.number}`);
}
function pullGlobalId(repo: Repo, pull: Pull): string {
  return b64encode(`pr:${repo.id}:${pull.number}`);
}
function commentGlobalId(repo: Repo, comment: IssueComment): string {
  return b64encode(`comment:${repo.id}:${comment.id}`);
}
function decodeGlobalId(id: string): { kind: string; repoId: number; num: number } | null {
  try {
    const text = b64decode(id);
    const parts = text.split(':');
    if (parts.length < 2) return null;
    const repoId = Number(parts[1]);
    if (!Number.isInteger(repoId) || repoId <= 0) return null;
    return { kind: parts[0], repoId, num: parts.length > 2 ? Number(parts[2]) : 0 };
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------- object access
function getObject(repo: Repo, oid: string): GitObject | undefined {
  return repo.objects.get(oid);
}
function putObject(repo: Repo, type: ObjType, data: Buffer): string {
  const oid = hashObject(type, data);
  if (!repo.objects.has(oid)) repo.objects.set(oid, { type, data });
  return oid;
}
function getCommit(repo: Repo, oid: string): CommitInfo | undefined {
  let info = repo.commitCache.get(oid);
  if (info !== undefined) return info;
  const obj = repo.objects.get(oid);
  if (!obj || obj.type !== 'commit') return undefined;
  info = parseCommit(obj.data);
  repo.commitCache.set(oid, info);
  return info;
}
function getTree(repo: Repo, oid: string): TreeEntry[] | undefined {
  let entries = repo.treeCache.get(oid);
  if (entries !== undefined) return entries;
  const obj = repo.objects.get(oid);
  if (!obj || obj.type !== 'tree') return undefined;
  entries = parseTree(obj.data);
  repo.treeCache.set(oid, entries);
  return entries;
}
function refTarget(repo: Repo, ref: string): string | undefined {
  return repo.refs.get(ref);
}
function resolveRef(repo: Repo, ref: string): string | undefined {
  // ref may be a branch name, a full refname, or a commit oid.
  if (ref.startsWith('refs/')) return repo.refs.get(ref);
  const byHead = repo.refs.get(`refs/heads/${ref}`);
  if (byHead !== undefined) return byHead;
  if (isOid(ref) && repo.objects.has(ref)) return ref;
  return undefined;
}
function flattenTree(repo: Repo, treeOid: string | null, prefix: string, out: Map<string, { oid: string; mode: string }>): void {
  if (treeOid === null) return;
  const entries = getTree(repo, treeOid);
  if (!entries) return;
  for (const e of entries) {
    const path = prefix ? `${prefix}/${e.name}` : e.name;
    if (e.mode === '40000') flattenTree(repo, e.oid, path, out);
    else out.set(path, { oid: e.oid, mode: e.mode });
  }
}
// Replace the file at `path` in the tree rooted at `rootOid` (null = empty
// tree) with `blobOid` (null = delete the file). Returns the new root tree oid.
function setTreePath(repo: Repo, rootOid: string | null, segments: string[], blobOid: string | null): string {
  if (segments.length === 0) return rootOid ?? putObject(repo, 'tree', Buffer.alloc(0));
  const entries = rootOid !== null ? [...(getTree(repo, rootOid) ?? [])] : [];
  const name = segments[0];
  const idx = entries.findIndex((e) => e.name === name);
  if (segments.length === 1) {
    if (blobOid === null) {
      if (idx >= 0) entries.splice(idx, 1);
    } else {
      const entry: TreeEntry = { mode: '100644', name, oid: blobOid };
      if (idx >= 0) entries[idx] = entry;
      else entries.push(entry);
    }
  } else {
    const childOid = idx >= 0 && entries[idx].mode === '40000' ? entries[idx].oid : null;
    const newChild = setTreePath(repo, childOid, segments.slice(1), blobOid);
    const entry: TreeEntry = { mode: '40000', name, oid: newChild };
    if (idx >= 0) entries[idx] = entry;
    else entries.push(entry);
  }
  const built = buildTree(entries);
  repo.objects.set(built.oid, { type: 'tree', data: built.data });
  return built.oid;
}
function commitTree(repo: Repo, commitOid: string): string | null {
  const info = getCommit(repo, commitOid);
  return info ? info.tree : null;
}
// Walk commits from `tips` (newest first). Returns commit oids in walk order.
function walkCommits(repo: Repo, tips: string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  const stack = [...tips];
  while (stack.length > 0) {
    const oid = stack.pop() as string;
    if (seen.has(oid)) continue;
    const info = getCommit(repo, oid);
    if (!info) continue;
    seen.add(oid);
    out.push(oid);
    for (let i = info.parents.length - 1; i >= 0; i--) stack.push(info.parents[i]);
  }
  return out;
}
// Full closure of all objects reachable from `tips` (commits, trees, blobs, tags).
function reachableObjects(repo: Repo, tips: string[]): Set<string> {
  const seen = new Set<string>();
  const stack = [...tips];
  while (stack.length > 0) {
    const oid = stack.pop() as string;
    if (seen.has(oid)) continue;
    const obj = repo.objects.get(oid);
    if (!obj) continue;
    seen.add(oid);
    if (obj.type === 'commit') {
      const info = getCommit(repo, oid);
      if (info) {
        stack.push(info.tree);
        for (const p of info.parents) stack.push(p);
      }
    } else if (obj.type === 'tree') {
      const entries = getTree(repo, oid);
      if (entries) for (const e of entries) stack.push(e.oid);
    } else if (obj.type === 'tag') {
      const tag = parseTag(obj.data);
      stack.push(tag.object);
    }
  }
  return seen;
}
// True when `ancestor` is reachable from `descendant` (inclusive).
function isAncestor(repo: Repo, ancestor: string, descendant: string): boolean {
  if (ancestor === descendant) return true;
  const info = getCommit(repo, descendant);
  if (!info) return false;
  // Fast path: direct parent (the common case for sequential pushes).
  if (info.parents.includes(ancestor)) return true;
  const seen = new Set<string>();
  const stack = [...info.parents];
  while (stack.length > 0) {
    const oid = stack.pop() as string;
    if (oid === ancestor) return true;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const c = getCommit(repo, oid);
    if (c) for (const p of c.parents) stack.push(p);
  }
  return false;
}
function mergeBase(repo: Repo, a: string, b: string): string | null {
  const aSet = new Set(walkCommits(repo, [a]));
  const bWalk = walkCommits(repo, [b]);
  for (const oid of bWalk) if (aSet.has(oid)) return oid;
  return null;
}
interface FileDiff {
  filename: string;
  status: 'added' | 'modified' | 'removed';
  additions: number;
  deletions: number;
}
function lineCounts(oldBuf: Buffer | null, newBuf: Buffer | null): { additions: number; deletions: number } {
  const oldLines = oldBuf ? oldBuf.toString('utf8').split('\n') : [];
  const newLines = newBuf ? newBuf.toString('utf8').split('\n') : [];
  if (oldLines.length > 0 && oldLines[oldLines.length - 1] === '') oldLines.pop();
  if (newLines.length > 0 && newLines[newLines.length - 1] === '') newLines.pop();
  const oldCount = new Map<string, number>();
  for (const l of oldLines) oldCount.set(l, (oldCount.get(l) ?? 0) + 1);
  let additions = 0;
  const remaining = new Map(oldCount);
  for (const l of newLines) {
    const n = remaining.get(l) ?? 0;
    if (n > 0) remaining.set(l, n - 1);
    else additions++;
  }
  let deletions = 0;
  for (const n of remaining.values()) deletions += n;
  return { additions, deletions };
}
function diffTrees(repo: Repo, baseTree: string | null, headTree: string | null): FileDiff[] {
  const base = new Map<string, { oid: string; mode: string }>();
  const head = new Map<string, { oid: string; mode: string }>();
  flattenTree(repo, baseTree, '', base);
  flattenTree(repo, headTree, '', head);
  const paths = new Set([...base.keys(), ...head.keys()]);
  const out: FileDiff[] = [];
  for (const path of paths) {
    const b = base.get(path);
    const h = head.get(path);
    if (b && !h) {
      out.push({ filename: path, status: 'removed', additions: 0, deletions: lineCounts(repo.objects.get(b.oid)?.data ?? null, null).deletions });
    } else if (!b && h) {
      const counts = lineCounts(null, repo.objects.get(h.oid)?.data ?? null);
      out.push({ filename: path, status: 'added', additions: counts.additions, deletions: 0 });
    } else if (b && h && b.oid !== h.oid) {
      const counts = lineCounts(repo.objects.get(b.oid)?.data ?? null, repo.objects.get(h.oid)?.data ?? null);
      out.push({ filename: path, status: 'modified', additions: counts.additions, deletions: counts.deletions });
    }
  }
  out.sort((x, y) => (x.filename < y.filename ? -1 : x.filename > y.filename ? 1 : 0));
  return out;
}
// Three-way conflict test: both sides changed the same path differently from
// the merge-base.
function hasMergeConflict(repo: Repo, baseOid: string, headOid: string): boolean {
  const mb = mergeBase(repo, baseOid, headOid);
  const baseTree = mb ? commitTree(repo, mb) : null;
  const curTree = commitTree(repo, baseOid);
  const headTree = commitTree(repo, headOid);
  const base = new Map<string, { oid: string }>();
  const cur = new Map<string, { oid: string }>();
  const head = new Map<string, { oid: string }>();
  flattenTree(repo, baseTree, '', base);
  flattenTree(repo, curTree, '', cur);
  flattenTree(repo, headTree, '', head);
  const paths = new Set([...base.keys(), ...cur.keys(), ...head.keys()]);
  for (const p of paths) {
    const b = base.get(p)?.oid ?? null;
    const c = cur.get(p)?.oid ?? null;
    const h = head.get(p)?.oid ?? null;
    if (h !== b && c !== b && h !== c) return true;
  }
  return false;
}

// ---------------------------------------------------------------- HTTP plumbing
const TOKEN: string = process.env.MAKEFUN_SHOP_TOKEN ?? '';
const ENV_URL: string = process.env.MAKEFUN_ENV_URL ?? '';
const IS_LIFECYCLE = ENV_URL.length > 0;
const AUTH_TOKEN = TOKEN.length > 0 ? TOKEN : IS_LIFECYCLE ? '' : 'test-token';
let requestSeq = 0;

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}
function sendJson(res: ServerResponse, status: number, value: unknown, extra?: Record<string, string>): void {
  sendJsonText(res, status, JSON.stringify(value), extra);
}
function sendJsonText(res: ServerResponse, status: number, body: string, extra?: Record<string, string>): void {
  const headers: Record<string, string> = {
    'content-type': 'application/json; charset=utf-8',
    'x-github-request-id': `req-${++requestSeq}`,
    'x-oauth-scopes': 'repo, read:org',
    ...(extra ?? {}),
  };
  res.writeHead(status, headers);
  res.end(body);
}
function sendNoContent(res: ServerResponse): void {
  res.writeHead(204, {
    'content-type': 'application/json; charset=utf-8',
    'x-github-request-id': `req-${++requestSeq}`,
    'x-oauth-scopes': 'repo, read:org',
  });
  res.end();
}
function sendError(res: ServerResponse, status: number, message: string): void {
  sendJson(res, status, { message });
}
function isAuthorized(req: IncomingMessage): boolean {
  if (AUTH_TOKEN.length === 0) return false;
  return req.headers.authorization === `Bearer ${AUTH_TOKEN}`;
}
function parseJsonBody(buf: Buffer): { ok: boolean; value: unknown } {
  if (buf.length === 0) return { ok: true, value: null };
  try {
    return { ok: true, value: JSON.parse(buf.toString('utf8')) };
  } catch {
    return { ok: false, value: null };
  }
}
function asRecord(v: unknown): Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
}
function asString(v: unknown): string | undefined {
  return typeof v === 'string' ? v : undefined;
}
function pageParams(query: URLSearchParams): { perPage: number; page: number } {
  let perPage = Number(query.get('per_page') ?? '30');
  if (!Number.isFinite(perPage) || perPage < 1) perPage = 30;
  if (perPage > 100) perPage = 100;
  let page = Number(query.get('page') ?? '1');
  if (!Number.isFinite(page) || page < 1) page = 1;
  return { perPage: Math.floor(perPage), page: Math.floor(page) };
}
function paginate<T>(items: T[], query: URLSearchParams, baseUrl: string, path: string): { page: T[]; link: string | null } {
  const { perPage, page } = pageParams(query);
  const totalPages = Math.max(1, Math.ceil(items.length / perPage));
  const start = (page - 1) * perPage;
  const pageItems = items.slice(start, start + perPage);
  let link: string | null = null;
  if (totalPages > 1) {
    const make = (p: number): string => {
      const q = new URLSearchParams(query);
      q.set('per_page', String(perPage));
      q.set('page', String(p));
      return `<${baseUrl}${path}?${q.toString()}>`;
    };
    const parts: string[] = [];
    if (page < totalPages) parts.push(`${make(page + 1)}; rel="next"`);
    if (page > 1) parts.push(`${make(page - 1)}; rel="prev"`);
    parts.push(`${make(1)}; rel="first"`);
    parts.push(`${make(totalPages)}; rel="last"`);
    link = parts.join(', ');
  }
  return { page: pageItems, link };
}

// ---------------------------------------------------------------- REST serializers
function userJson(login: string): Record<string, unknown> {
  return { login, id: login === VIEWER_LOGIN ? VIEWER_ID : 0, type: 'User', avatar_url: '', html_url: `https://github.com/${login}` };
}
function repoJson(repo: Repo): Record<string, unknown> {
  return {
    id: repo.id,
    node_id: repoGlobalId(repo),
    name: repo.name,
    full_name: fullName(repo.owner, repo.name),
    owner: userJson(repo.owner),
    private: repo.isPrivate,
    description: repo.description,
    default_branch: repo.defaultBranch,
    html_url: `https://github.com/${repo.owner}/${repo.name}`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}`,
    clone_url: `https://github.com/${repo.owner}/${repo.name}.git`,
    git_url: `git://github.com/${repo.owner}/${repo.name}.git`,
    ssh_url: `git@github.com:${repo.owner}/${repo.name}.git`,
    created_at: FIXED_DATE,
    updated_at: FIXED_DATE,
    pushed_at: FIXED_DATE,
    has_issues: true,
    has_projects: true,
    has_wiki: true,
    fork: false,
    archived: false,
    disabled: false,
    visibility: repo.isPrivate ? 'private' : 'public',
    open_issues_count: repo.issues.filter((i) => i.state === 'open').length,
  };
}
function labelJson(label: Label): Record<string, unknown> {
  return { name: label.name, color: label.color, description: label.description };
}
function issueJson(repo: Repo, issue: Issue): Record<string, unknown> {
  return {
    id: issue.id,
    node_id: issueGlobalId(repo, issue),
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    user: userJson(issue.user),
    labels: issue.labels.map((n) => labelJson(repo.labels.get(n) ?? { name: n, color: '000000', description: '' })),
    comments: (repo.comments.get(issue.number) ?? []).length,
    created_at: FIXED_DATE,
    updated_at: FIXED_DATE,
    closed_at: issue.state === 'closed' ? FIXED_DATE : null,
    html_url: `https://github.com/${repo.owner}/${repo.name}/issues/${issue.number}`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}/issues/${issue.number}`,
    repository_url: `/api/v3/repos/${repo.owner}/${repo.name}`,
  };
}
// Serialized single-issue GET responses, keyed by repo + issue + viewVersion.
// viewVersion bumps on any mutation that can change an issue's JSON (create,
// patch, close, comment, label change); a stale key just misses, never lies.
const issueJsonCache = new Map<string, string>();
function cachedIssueJson(repo: Repo, issue: Issue): string {
  const key = `issue|${repo.id}|${issue.number}|${repo.viewVersion}`;
  const hit = issueJsonCache.get(key);
  if (hit !== undefined) return hit;
  const body = JSON.stringify(issueJson(repo, issue));
  if (issueJsonCache.size >= 1024) issueJsonCache.clear();
  issueJsonCache.set(key, body);
  return body;
}
function parseIdent(line: string): { name: string; email: string } {
  const m = /^(.+) <([^>]+)> \d+ [+-]\d{4}$/.exec(line);
  if (m) return { name: m[1], email: m[2] };
  return { name: VIEWER_NAME, email: VIEWER_EMAIL };
}
function commitJson(repo: Repo, oid: string): Record<string, unknown> | null {
  const info = getCommit(repo, oid);
  if (!info) return null;
  const author = parseIdent(info.author || `${VIEWER_NAME} <${VIEWER_EMAIL}> ${COMMIT_TS} +0000`);
  const committer = parseIdent(info.committer || info.author || `${VIEWER_NAME} <${VIEWER_EMAIL}> ${COMMIT_TS} +0000`);
  const message = info.message.replace(/\n$/, '');
  return {
    sha: oid,
    node_id: b64encode(`commit:${repo.id}:${oid}`),
    commit: {
      message,
      author: { name: author.name, email: author.email, date: FIXED_DATE },
      committer: { name: committer.name, email: committer.email, date: FIXED_DATE },
      tree: { sha: info.tree },
    },
    author: userJson(VIEWER_LOGIN),
    committer: userJson(VIEWER_LOGIN),
    parents: info.parents.map((p) => ({ sha: p })),
    url: `/api/v3/repos/${repo.owner}/${repo.name}/commits/${oid}`,
    html_url: `https://github.com/${repo.owner}/${repo.name}/commit/${oid}`,
  };
}
function pullJson(repo: Repo, pull: Pull): Record<string, unknown> {
  const mergeable = pull.merged ? true : !hasMergeConflict(repo, pull.baseSha, pull.headSha);
  return {
    id: pull.id,
    node_id: pullGlobalId(repo, pull),
    number: pull.number,
    title: pull.title,
    body: pull.body,
    state: pull.state,
    merged: pull.merged,
    mergeable,
    merge_commit_sha: pull.mergeCommitSha,
    merged_at: pull.mergedAt,
    head: { label: `${repo.owner}:${pull.headRef}`, ref: pull.headRef, sha: pull.headSha, user: userJson(repo.owner), repo: repoJson(repo) },
    base: { label: `${repo.owner}:${pull.baseRef}`, ref: pull.baseRef, sha: pull.baseSha, user: userJson(repo.owner), repo: repoJson(repo) },
    user: userJson(repo.owner),
    created_at: FIXED_DATE,
    updated_at: FIXED_DATE,
    closed_at: pull.state === 'closed' ? FIXED_DATE : null,
    html_url: `https://github.com/${repo.owner}/${repo.name}/pull/${pull.number}`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}/pulls/${pull.number}`,
  };
}
function createIssueInternal(repo: Repo, title: string, body: string, labels: string[]): Issue {
  const issue: Issue = {
    id: store.nextIssueId++,
    number: repo.nextIssue++,
    title,
    body,
    state: 'open',
    labels,
    seq: ++store.seq,
    user: VIEWER_LOGIN,
  };
  repo.issues.push(issue);
  repo.viewVersion++;
  return issue;
}
function createPullInternal(repo: Repo, title: string, body: string, headRef: string, headSha: string, baseRef: string, baseSha: string): Pull {
  const pull: Pull = {
    id: store.nextPullId++,
    number: repo.nextPull++,
    title,
    body,
    state: 'open',
    merged: false,
    mergedAt: null,
    mergeCommitSha: null,
    headRef,
    headSha,
    baseRef,
    baseSha,
    seq: ++store.seq,
  };
  repo.pulls.push(pull);
  return pull;
}
function stripBranchPrefix(ref: string): string {
  const idx = ref.indexOf(':');
  return idx >= 0 ? ref.slice(idx + 1) : ref;
}

// ---------------------------------------------------------------- REST v3
async function handleRest(req: IncomingMessage, res: ServerResponse, segments: string[], query: URLSearchParams, bodyBuf: Buffer): Promise<void> {
  const method = req.method ?? 'GET';
  const host = req.headers.host ?? '127.0.0.1';
  const baseUrl = `http://${host}`;
  const path = '/' + segments.join('/');

  // GET /api/v3  (root)
  if (segments.length === 2) {
    if (method !== 'GET') return sendError(res, 404, 'Not Found');
    return sendJson(res, 200, {
      current_user_url: `${baseUrl}/api/v3/user`,
      repository_url: `${baseUrl}/api/v3/repos/{owner}/{repo}`,
      user_url: `${baseUrl}/api/v3/users/{user}`,
      meta: { installed_version: VERSION },
    });
  }
  // GET /api/v3/meta
  if (segments.length === 3 && segments[2] === 'meta') {
    if (method !== 'GET') return sendError(res, 404, 'Not Found');
    return sendJson(res, 200, { installed_version: VERSION, verifiable_password_authentication: true, github_services_sha: '0000000000000000000000000000000000000000' });
  }
  // GET /api/v3/user
  if (segments.length === 3 && segments[2] === 'user') {
    if (method !== 'GET') return sendError(res, 404, 'Not Found');
    return sendJson(res, 200, {
      login: VIEWER_LOGIN, id: VIEWER_ID, node_id: b64encode(`user:${VIEWER_ID}`), name: VIEWER_NAME,
      email: VIEWER_EMAIL, type: 'User', avatar_url: '', html_url: `https://github.com/${VIEWER_LOGIN}`,
      created_at: FIXED_DATE, updated_at: FIXED_DATE, site_admin: false,
    });
  }
  // /api/v3/user/repos
  if (segments.length === 4 && segments[2] === 'user' && segments[3] === 'repos') {
    if (method === 'GET') {
      const { page, link } = paginate(viewerRepos().map(repoJson), query, baseUrl, path);
      return sendJson(res, 200, page, link ? { link } : undefined);
    }
    if (method === 'POST') {
      const parsed = parseJsonBody(bodyBuf);
      if (!parsed.ok) return sendError(res, 400, 'Problems parsing JSON');
      const body = asRecord(parsed.value);
      const name = asString(body.name);
      if (name === undefined || name.length === 0) return sendError(res, 422, 'name is required');
      if (getRepo(VIEWER_LOGIN, name) !== undefined) return sendError(res, 422, 'Repository already exists');
      const repo = createRepo(VIEWER_LOGIN, name, asString(body.description) ?? '', body.private === true);
      return sendJson(res, 201, repoJson(repo));
    }
    return sendError(res, 404, 'Not Found');
  }
  // /api/v3/repos/{owner}/{repo}[...]
  if (segments.length >= 5 && segments[2] === 'repos') {
    const owner = segments[3];
    const repoName = segments[4];
    const repo = getRepo(owner, repoName);
    if (repo === undefined) return sendError(res, 404, 'Not Found');
    const rest = segments.slice(5);

    // /repos/{o}/{r}
    if (rest.length === 0) {
      if (method === 'GET') return sendJson(res, 200, repoJson(repo));
      if (method === 'PATCH') {
        const parsed = parseJsonBody(bodyBuf);
        if (!parsed.ok) return sendError(res, 400, 'Problems parsing JSON');
        const body = asRecord(parsed.value);
        if (asString(body.description) !== undefined) repo.description = asString(body.description) as string;
        if (typeof body.private === 'boolean') repo.isPrivate = body.private;
        return sendJson(res, 200, repoJson(repo));
      }
      if (method === 'DELETE') {
        deleteRepo(owner, repoName);
        return sendNoContent(res);
      }
      return sendError(res, 404, 'Not Found');
    }
    const section = rest[0];

    // ---- branches
    if (section === 'branches') {
      if (method !== 'GET') return sendError(res, 404, 'Not Found');
      if (rest.length === 1) {
        const list: Record<string, unknown>[] = [];
        for (const [ref, sha] of [...repo.refs.entries()].sort()) {
          if (ref.startsWith('refs/heads/')) list.push({ name: ref.slice(11), commit: { sha }, protected: false });
        }
        return sendJson(res, 200, list);
      }
      const branch = rest.slice(1).join('/');
      const sha = repo.refs.get(`refs/heads/${branch}`);
      if (sha === undefined) return sendError(res, 404, 'Not Found');
      return sendJson(res, 200, { name: branch, commit: { sha }, protected: false });
    }

    // ---- commits
    if (section === 'commits') {
      if (method !== 'GET') return sendError(res, 404, 'Not Found');
      const ref = query.get('sha') ?? repo.defaultBranch;
      const tip = resolveRef(repo, ref);
      if (tip === undefined) return sendJson(res, 200, []);
      const walked = walkCommits(repo, [tip]);
      const items = walked.map((oid) => commitJson(repo, oid)).filter((x): x is Record<string, unknown> => x !== null);
      const { page, link } = paginate(items, query, baseUrl, path);
      return sendJson(res, 200, page, link ? { link } : undefined);
    }

    // ---- git refs
    if (section === 'git' && rest[1] === 'refs') {
      if (method === 'POST' && rest.length === 2) {
        const parsed = parseJsonBody(bodyBuf);
        if (!parsed.ok) return sendError(res, 400, 'Problems parsing JSON');
        const body = asRecord(parsed.value);
        const ref = asString(body.ref);
        const sha = asString(body.sha);
        if (ref === undefined || !ref.startsWith('refs/') || sha === undefined || !isOid(sha)) {
          return sendError(res, 422, 'Invalid request');
        }
        if (repo.refs.has(ref)) return sendError(res, 422, 'Reference already exists');
        const obj = repo.objects.get(sha);
        if (obj === undefined || obj.type !== 'commit') return sendError(res, 422, 'Object does not exist');
        repo.refs.set(ref, sha);
        return sendJson(res, 201, { ref, node_id: b64encode(`ref:${repo.id}:${ref}`), object: { sha, type: 'commit', url: `/api/v3/repos/${owner}/${repoName}/git/commits/${sha}` } });
      }
      if (method === 'GET') {
        if (rest.length === 2) {
          const list: Record<string, unknown>[] = [];
          for (const [ref, sha] of [...repo.refs.entries()].sort()) {
            list.push({ ref, object: { sha, type: 'commit' } });
          }
          return sendJson(res, 200, list);
        }
        if (rest.length >= 4 && rest[2] === 'heads') {
          const branch = rest.slice(3).join('/');
          const sha = repo.refs.get(`refs/heads/${branch}`);
          if (sha === undefined) return sendError(res, 404, 'Not Found');
          return sendJson(res, 200, { ref: `refs/heads/${branch}`, object: { sha, type: 'commit' } });
        }
      }
      return sendError(res, 404, 'Not Found');
    }

    // ---- contents
    if (section === 'contents') {
      const filePath = rest.slice(1).join('/');
      if (method === 'PUT') {
        const parsed = parseJsonBody(bodyBuf);
        if (!parsed.ok) return sendError(res, 400, 'Problems parsing JSON');
        const body = asRecord(parsed.value);
        const message = asString(body.message) ?? 'Update file';
        const contentB64 = asString(body.content);
        if (contentB64 === undefined) return sendError(res, 422, 'content is required');
        const branch = asString(body.branch) ?? repo.defaultBranch;
        const refName = `refs/heads/${branch}`;
        let tip = repo.refs.get(refName);
        if (tip === undefined) {
          const defaultTip = repo.refs.get(`refs/heads/${repo.defaultBranch}`);
          tip = defaultTip; // create the branch from the default tip (or empty)
        }
        const content = Buffer.from(contentB64, 'base64');
        const blobOid = storeBlob(repo, content);
        const tipTree = tip !== undefined ? commitTree(repo, tip) : null;
        const flat = new Map<string, { oid: string; mode: string }>();
        flattenTree(repo, tipTree, '', flat);
        const existing = flat.get(filePath);
        const givenSha = asString(body.sha);
        if (existing !== undefined) {
          if (givenSha === undefined) return sendError(res, 422, "sha wasn't supplied");
          if (givenSha !== existing.oid) return sendError(res, 409, 'sha does not match');
        } else if (givenSha !== undefined) {
          return sendError(res, 422, 'Invalid request. Object does not exist');
        }
        const newTree = setTreePath(repo, tipTree, filePath.split('/'), blobOid);
        const built = buildCommit(newTree, tip !== undefined ? [tip] : [], message);
        repo.objects.set(built.oid, { type: 'commit', data: built.data });
        repo.refs.set(refName, built.oid);
        const name = filePath.split('/').pop() ?? filePath;
        return sendJson(res, existing !== undefined ? 200 : 201, {
          content: { name, path: filePath, sha: blobOid, size: content.length, type: 'file', encoding: 'base64', content: contentB64, url: `/api/v3/repos/${owner}/${repoName}/contents/${filePath}` },
          commit: { sha: built.oid, message },
        });
      }
      if (method === 'GET') {
        const ref = query.get('ref') ?? repo.defaultBranch;
        const tip = resolveRef(repo, ref);
        if (tip === undefined) return sendError(res, 404, 'Not Found');
        const tree = commitTree(repo, tip);
        const flat = new Map<string, { oid: string; mode: string }>();
        flattenTree(repo, tree, '', flat);
        if (filePath === '') {
          // Root directory listing.
          const entries = new Map<string, { oid: string; mode: string }>();
          const rootEntries = tree !== null ? getTree(repo, tree) ?? [] : [];
          for (const e of rootEntries) entries.set(e.name, { oid: e.oid, mode: e.mode });
          const list = [...entries.entries()].map(([name, e]) => ({
            type: e.mode === '40000' ? 'dir' : 'file',
            name,
            path: name,
            sha: e.oid,
            size: e.mode === '40000' ? undefined : (repo.objects.get(e.oid)?.data.length ?? 0),
            url: `/api/v3/repos/${owner}/${repoName}/contents/${name}`,
          }));
          list.sort((a, b) => (a.name < b.name ? -1 : 1));
          return sendJson(res, 200, list);
        }
        const file = flat.get(filePath);
        if (file !== undefined) {
          const data = repo.objects.get(file.oid)?.data ?? Buffer.alloc(0);
          return sendJson(res, 200, {
            type: 'file', encoding: 'base64', size: data.length, name: filePath.split('/').pop() ?? filePath,
            path: filePath, content: data.toString('base64'), sha: file.oid,
            url: `/api/v3/repos/${owner}/${repoName}/contents/${filePath}`,
          });
        }
        // Directory?
        const prefix = filePath + '/';
        const children = new Map<string, { oid: string; mode: string }>();
        for (const [p, e] of flat) {
          if (!p.startsWith(prefix)) continue;
          const rest2 = p.slice(prefix.length);
          if (!rest2.includes('/')) children.set(rest2, e);
        }
        if (children.size === 0) {
          // Maybe a directory that only contains subdirectories.
          const subdirs = new Set<string>();
          for (const p of flat.keys()) {
            if (!p.startsWith(prefix)) continue;
            const rest2 = p.slice(prefix.length);
            const first = rest2.split('/')[0];
            if (first.length > 0) subdirs.add(first);
          }
          if (subdirs.size === 0) return sendError(res, 404, 'Not Found');
          const list = [...subdirs].sort().map((name) => ({
            type: 'dir', name, path: `${filePath}/${name}`,
            sha: '', url: `/api/v3/repos/${owner}/${repoName}/contents/${filePath}/${name}`,
          }));
          // Fill directory shas from the tree.
          const dirEntries = findDirEntries(repo, tree, filePath);
          for (const item of list) {
            const hit = dirEntries.find((e) => e.name === item.name);
            if (hit) item.sha = hit.oid;
          }
          return sendJson(res, 200, list);
        }
        const list = [...children.entries()].map(([name, e]) => ({
          type: e.mode === '40000' ? 'dir' : 'file',
          name,
          path: `${filePath}/${name}`,
          sha: e.oid,
          size: e.mode === '40000' ? undefined : (repo.objects.get(e.oid)?.data.length ?? 0),
          url: `/api/v3/repos/${owner}/${repoName}/contents/${filePath}/${name}`,
        }));
        list.sort((a, b) => (a.name < b.name ? -1 : 1));
        return sendJson(res, 200, list);
      }
      if (method === 'DELETE') {
        const parsed = parseJsonBody(bodyBuf);
        if (!parsed.ok) return sendError(res, 400, 'Problems parsing JSON');
        const body = asRecord(parsed.value);
        const message = asString(body.message) ?? 'Delete file';
        const branch = asString(body.branch) ?? repo.defaultBranch;
        const refName = `refs/heads/${branch}`;
        const tip = repo.refs.get(refName);
        if (tip === undefined) return sendError(res, 404, 'Not Found');
        const tipTree = commitTree(repo, tip);
        const flat = new Map<string, { oid: string; mode: string }>();
        flattenTree(repo, tipTree, '', flat);
        if (!flat.has(filePath)) return sendError(res, 404, 'Not Found');
        const newTree = setTreePath(repo, tipTree, filePath.split('/'), null);
        const built = buildCommit(newTree, [tip], message);
        repo.objects.set(built.oid, { type: 'commit', data: built.data });
        repo.refs.set(refName, built.oid);
        return sendJson(res, 200, { commit: { sha: built.oid, message } });
      }
      return sendError(res, 404, 'Not Found');
    }

    // ---- labels
    if (section === 'labels') {
      if (method === 'GET') {
        return sendJson(res, 200, [...repo.labels.values()].map(labelJson));
      }
      if (method === 'POST') {
        const parsed = parseJsonBody(bodyBuf);
        if (!parsed.ok) return sendError(res, 400, 'Problems parsing JSON');
        const body = asRecord(parsed.value);
        const name = asString(body.name);
        if (name === undefined || name.length === 0) return sendError(res, 422, 'name is required');
        const existing = repo.labels.get(name);
        if (existing !== undefined) return sendJson(res, 201, labelJson(existing));
        const label: Label = { name, color: asString(body.color) ?? '000000', description: asString(body.description) ?? '' };
        repo.labels.set(name, label);
        repo.viewVersion++;
        return sendJson(res, 201, labelJson(label));
      }
      return sendError(res, 404, 'Not Found');
    }

    // ---- issues
    if (section === 'issues') {
      if (rest.length === 1) {
        if (method === 'GET') {
          const state = query.get('state') ?? 'open';
          let list = [...repo.issues];
          if (state === 'open') list = list.filter((i) => i.state === 'open');
          else if (state === 'closed') list = list.filter((i) => i.state === 'closed');
          const direction = query.get('direction') ?? 'desc';
          list.sort((a, b) => (direction === 'asc' ? a.seq - b.seq : b.seq - a.seq));
          const { page, link } = paginate(list.map((i) => issueJson(repo, i)), query, baseUrl, path);
          return sendJson(res, 200, page, link ? { link } : undefined);
        }
        if (method === 'POST') {
          const parsed = parseJsonBody(bodyBuf);
          if (!parsed.ok) return sendError(res, 400, 'Problems parsing JSON');
          const body = asRecord(parsed.value);
          const title = asString(body.title);
          if (title === undefined || title.length === 0) return sendError(res, 422, 'title is required');
          const labelNames: string[] = Array.isArray(body.labels) ? body.labels.filter((x): x is string => typeof x === 'string') : [];
          for (const n of labelNames) {
            if (!repo.labels.has(n)) return sendError(res, 422, `Label does not exist: ${n}`);
          }
          const issue = createIssueInternal(repo, title, asString(body.body) ?? '', labelNames);
          return sendJson(res, 201, issueJson(repo, issue));
        }
        return sendError(res, 404, 'Not Found');
      }
      const num = Number(rest[1]);
      if (!Number.isInteger(num) || num <= 0) return sendError(res, 404, 'Not Found');
      const issue = repo.issues.find((i) => i.number === num);
      if (issue === undefined) return sendError(res, 404, 'Not Found');
      if (rest.length === 2) {
        if (method === 'GET') return sendJsonText(res, 200, cachedIssueJson(repo, issue));
        if (method === 'PATCH') {
          const parsed = parseJsonBody(bodyBuf);
          if (!parsed.ok) return sendError(res, 400, 'Problems parsing JSON');
          const body = asRecord(parsed.value);
          if (asString(body.title) !== undefined) issue.title = asString(body.title) as string;
          if (asString(body.body) !== undefined) issue.body = asString(body.body) as string;
          if (body.state === 'open' || body.state === 'closed') issue.state = body.state;
          repo.viewVersion++;
          return sendJson(res, 200, issueJson(repo, issue));
        }
        return sendError(res, 404, 'Not Found');
      }
      if (rest.length === 3 && rest[2] === 'comments') {
        if (method === 'GET') {
          const list = repo.comments.get(num) ?? [];
          return sendJson(res, 200, list.map((c) => ({
            id: c.id, node_id: commentGlobalId(repo, c), body: c.body, user: userJson(c.user),
            created_at: FIXED_DATE, updated_at: FIXED_DATE,
            html_url: `https://github.com/${owner}/${repoName}/issues/${num}#issuecomment-${c.id}`,
          })));
        }
        if (method === 'POST') {
          const parsed = parseJsonBody(bodyBuf);
          if (!parsed.ok) return sendError(res, 400, 'Problems parsing JSON');
          const body = asRecord(parsed.value);
          const commentBody = asString(body.body);
          if (commentBody === undefined) return sendError(res, 422, 'body is required');
          const comment: IssueComment = { id: repo.nextCommentId++, body: commentBody, user: VIEWER_LOGIN };
          const list = repo.comments.get(num) ?? [];
          list.push(comment);
          repo.comments.set(num, list);
          repo.viewVersion++;
          return sendJson(res, 201, {
            id: comment.id, node_id: commentGlobalId(repo, comment), body: comment.body, user: userJson(comment.user),
            created_at: FIXED_DATE, updated_at: FIXED_DATE,
            html_url: `https://github.com/${owner}/${repoName}/issues/${num}#issuecomment-${comment.id}`,
          });
        }
        return sendError(res, 404, 'Not Found');
      }
      return sendError(res, 404, 'Not Found');
    }

    // ---- pulls
    if (section === 'pulls') {
      if (rest.length === 1) {
        if (method === 'GET') {
          const state = query.get('state') ?? 'open';
          let list = [...repo.pulls];
          if (state === 'open') list = list.filter((p) => p.state === 'open');
          else if (state === 'closed') list = list.filter((p) => p.state === 'closed');
          list.sort((a, b) => b.seq - a.seq);
          const { page, link } = paginate(list.map((p) => pullJson(repo, p)), query, baseUrl, path);
          return sendJson(res, 200, page, link ? { link } : undefined);
        }
        if (method === 'POST') {
          const parsed = parseJsonBody(bodyBuf);
          if (!parsed.ok) return sendError(res, 400, 'Problems parsing JSON');
          const body = asRecord(parsed.value);
          const title = asString(body.title);
          const headRaw = asString(body.head);
          const baseRaw = asString(body.base);
          if (title === undefined || headRaw === undefined || baseRaw === undefined) {
            return sendError(res, 422, 'title, head and base are required');
          }
          const headRef = stripBranchPrefix(headRaw);
          const baseRef = stripBranchPrefix(baseRaw);
          const headSha = repo.refs.get(`refs/heads/${headRef}`);
          const baseSha = repo.refs.get(`refs/heads/${baseRef}`);
          if (headSha === undefined || baseSha === undefined) {
            return sendError(res, 422, 'Invalid request. Head or base does not exist');
          }
          const dup = repo.pulls.find((p) => p.state === 'open' && p.headRef === headRef && p.baseRef === baseRef);
          if (dup !== undefined) return sendError(res, 422, 'A pull request already exists for this head and base');
          const pull = createPullInternal(repo, title, asString(body.body) ?? '', headRef, headSha, baseRef, baseSha);
          return sendJson(res, 201, pullJson(repo, pull));
        }
        return sendError(res, 404, 'Not Found');
      }
      const num = Number(rest[1]);
      if (!Number.isInteger(num) || num <= 0) return sendError(res, 404, 'Not Found');
      const pull = repo.pulls.find((p) => p.number === num);
      if (pull === undefined) return sendError(res, 404, 'Not Found');
      if (rest.length === 2) {
        if (method === 'GET') return sendJson(res, 200, pullJson(repo, pull));
        return sendError(res, 404, 'Not Found');
      }
      if (rest.length === 3 && rest[2] === 'files') {
        if (method !== 'GET') return sendError(res, 404, 'Not Found');
        const baseTree = commitTree(repo, pull.baseSha);
        const headTree = commitTree(repo, pull.headSha);
        const files = diffTrees(repo, baseTree, headTree).map((f) => ({
          filename: f.filename, status: f.status, additions: f.additions, deletions: f.deletions,
          changes: f.additions + f.deletions, sha: '', blob_url: '', raw_url: '',
        }));
        return sendJson(res, 200, files);
      }
      if (rest.length === 3 && rest[2] === 'merge') {
        if (method !== 'PUT') return sendError(res, 404, 'Not Found');
        if (pull.merged || pull.state === 'closed') return sendError(res, 405, 'Pull request is already merged or closed');
        const baseTip = repo.refs.get(`refs/heads/${pull.baseRef}`);
        if (baseTip === undefined || baseTip !== pull.baseSha) return sendError(res, 405, 'Base branch has moved');
        if (hasMergeConflict(repo, pull.baseSha, pull.headSha)) {
          return sendError(res, 405, 'Merge conflict');
        }
        const headTree = commitTree(repo, pull.headSha);
        const message = `Merge pull request #${pull.number} from ${owner}/${pull.headRef}`;
        const built = buildCommit(headTree ?? putObject(repo, 'tree', Buffer.alloc(0)), [pull.baseSha], message);
        repo.objects.set(built.oid, { type: 'commit', data: built.data });
        repo.refs.set(`refs/heads/${pull.baseRef}`, built.oid);
        pull.merged = true;
        pull.state = 'closed';
        pull.mergedAt = FIXED_DATE;
        pull.mergeCommitSha = built.oid;
        return sendJson(res, 200, { sha: built.oid, merged: true, message: 'Pull request successfully merged' });
      }
      return sendError(res, 404, 'Not Found');
    }
    return sendError(res, 404, 'Not Found');
  }
  return sendError(res, 404, 'Not Found');
}
// Entries of the tree at `dirPath` ('' = root) inside `rootOid`.
function findDirEntries(repo: Repo, rootOid: string | null, dirPath: string): TreeEntry[] {
  if (rootOid === null) return [];
  let current: TreeEntry[] | undefined = getTree(repo, rootOid);
  if (dirPath === '') return current ?? [];
  for (const seg of dirPath.split('/')) {
    const hit = current?.find((e) => e.name === seg && e.mode === '40000');
    if (!hit) return [];
    current = getTree(repo, hit.oid);
  }
  return current ?? [];
}

// ---------------------------------------------------------------- response caches
// Hot git responses are pure functions of (repo state, request args): objects are
// immutable (oid = content hash) and only ever added, refs change only via an
// update, so a cache keyed on the exact inputs is exact — a changed input just
// misses, no invalidation bookkeeping to get wrong. Bounded; clears when full.
const responseCache = new Map<string, Buffer>();
function cachedResponse(key: string, build: () => Buffer): Buffer {
  const hit = responseCache.get(key);
  if (hit !== undefined) return hit;
  const built = build();
  if (responseCache.size >= 512) responseCache.clear();
  responseCache.set(key, built);
  return built;
}
function refsKey(repo: Repo): string {
  return [...repo.refs.entries()]
    .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))
    .map(([r, o]) => `${r}=${o}`)
    .join(',');
}

// ---------------------------------------------------------------- git smart HTTP
function sendGit(res: ServerResponse, status: number, contentType: string, body: Buffer): void {
  res.writeHead(status, { 'content-type': contentType, 'content-length': String(body.length) });
  res.end(body);
}
function refAdvertisementLines(repo: Repo, caps: string): Buffer[] {
  const lines: string[] = [];
  const refs = [...repo.refs.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1));
  const mainTip = repo.refs.get('refs/heads/main');
  if (mainTip !== undefined) lines.push(`${mainTip} HEAD`);
  else if (refs.length === 0) lines.push(`${ZERO_OID} capabilities^{}`);
  for (const [ref, oid] of refs) {
    if (ref === 'refs/heads/main' && mainTip !== undefined) {
      // HEAD line already carries the tip; still list the branch itself.
      lines.push(`${oid} ${ref}`);
      continue;
    }
    lines.push(`${oid} ${ref}`);
    if (ref.startsWith('refs/tags/')) {
      const obj = repo.objects.get(oid);
      if (obj && obj.type === 'tag') {
        const tag = parseTag(obj.data);
        if (isOid(tag.object)) lines.push(`${tag.object} ${ref}^{}`);
      }
    }
  }
  const out: Buffer[] = [];
  lines.forEach((line, i) => {
    out.push(pktLine(i === 0 ? `${line}\0${caps}\n` : `${line}\n`));
  });
  return out;
}
interface FetchPlan {
  objects: GitObject[];
  acks: string[];
  nak: boolean;
  shallow: string[];
  unshallow: string[];
}
// Closure of objects the client already has. A commit listed in `boundaries`
// is a shallow boundary: the client has the commit itself (and its tree) but
// none of its ancestors, so the walk stops there.
function haveClosure(repo: Repo, haves: string[], boundaries: Set<string>): Set<string> {
  const seen = new Set<string>();
  const stack = [...haves];
  while (stack.length > 0) {
    const oid = stack.pop() as string;
    if (seen.has(oid)) continue;
    const obj = repo.objects.get(oid);
    if (!obj) continue;
    seen.add(oid);
    if (obj.type === 'commit') {
      const info = getCommit(repo, oid);
      if (!info) continue;
      stack.push(info.tree);
      if (!boundaries.has(oid)) for (const p of info.parents) stack.push(p);
    } else if (obj.type === 'tree') {
      const entries = getTree(repo, oid);
      if (entries) for (const e of entries) stack.push(e.oid);
    } else if (obj.type === 'tag') {
      const tag = parseTag(obj.data);
      stack.push(tag.object);
    }
  }
  return seen;
}
function planFetch(repo: Repo, wants: string[], haves: string[], depth: number | null, oldShallow: string[]): FetchPlan {
  const haveSet = haveClosure(repo, haves, new Set(oldShallow));
  const included = new Set<string>();
  const shallowSet = new Set<string>();
  const visited = new Set<string>();
  const queue: Array<[string, number]> = [];
  for (const w of wants) {
    const obj = repo.objects.get(w);
    if (!obj) continue;
    if (obj.type === 'tag') {
      included.add(w);
      const tag = parseTag(obj.data);
      if (isOid(tag.object)) queue.push([tag.object, 0]);
    } else if (obj.type === 'commit') {
      queue.push([w, 0]);
    }
  }
  // Index pointer, not shift(): shift() is O(n) per pop on a long history walk.
  let qhead = 0;
  while (qhead < queue.length) {
    const [oid, gen] = queue[qhead++] as [string, number];
    if (visited.has(oid)) continue;
    visited.add(oid);
    const info = getCommit(repo, oid);
    if (!info) continue;
    if (depth !== null && gen >= depth) continue;
    included.add(oid);
    for (const parent of info.parents) {
      if (haveSet.has(parent)) {
        shallowSet.add(oid);
      } else if (depth !== null && gen + 1 >= depth) {
        shallowSet.add(oid);
      } else {
        queue.push([parent, gen + 1]);
      }
    }
  }
  // Expand trees/blobs of included commits.
  const expanded = new Set<string>(included);
  const stack: string[] = [...included];
  while (stack.length > 0) {
    const oid = stack.pop() as string;
    const obj = repo.objects.get(oid);
    if (!obj) continue;
    if (obj.type === 'commit') {
      const info = getCommit(repo, oid);
      if (info && !expanded.has(info.tree)) {
        expanded.add(info.tree);
        stack.push(info.tree);
      }
    } else if (obj.type === 'tree') {
      const entries = getTree(repo, oid);
      if (entries) {
        for (const e of entries) {
          if (!expanded.has(e.oid)) {
            expanded.add(e.oid);
            stack.push(e.oid);
          }
        }
      }
    } else if (obj.type === 'tag') {
      const tag = parseTag(obj.data);
      if (isOid(tag.object) && !expanded.has(tag.object)) {
        expanded.add(tag.object);
        stack.push(tag.object);
      }
    }
  }
  const objects: GitObject[] = [];
  for (const oid of expanded) {
    if (haveSet.has(oid)) continue;
    const obj = repo.objects.get(oid);
    if (obj) objects.push(obj);
  }
  const acks: string[] = [];
  let nak = false;
  if (haves.length === 0) {
    nak = true;
  } else {
    for (const h of haves) if (repo.objects.has(h)) acks.push(h);
    if (acks.length === 0) nak = true;
  }
  const shallow = depth !== null ? [...shallowSet].sort() : [];
  const unshallow = depth !== null ? oldShallow.filter((oid) => included.has(oid) && !shallowSet.has(oid)) : [];
  return { objects, acks, nak, shallow, unshallow };
}
function sidebandPack(pack: Buffer): Buffer {
  const parts: Buffer[] = [];
  for (let off = 0; off < pack.length; off += 65515) {
    const chunk = pack.subarray(off, Math.min(pack.length, off + 65515));
    parts.push(pktLine(Buffer.concat([Buffer.from([0x01]), chunk])));
  }
  return Buffer.concat(parts);
}
function lsRefsResponse(repo: Repo, args: string[]): Buffer {
  return cachedResponse(`lsrefs|${repo.id}|${refsKey(repo)}|${args.join('\n')}`, () => buildLsRefsResponse(repo, args));
}
function buildLsRefsResponse(repo: Repo, args: string[]): Buffer {
  const peel = args.includes('peel');
  const symrefs = args.includes('symrefs');
  const unborn = args.includes('unborn');
  const prefixes = args.filter((a) => a.startsWith('ref-prefix ')).map((a) => a.slice(11));
  const matches = (name: string): boolean => prefixes.length === 0 || prefixes.some((p) => name.startsWith(p));
  const lines: string[] = [];
  const mainTip = repo.refs.get('refs/heads/main');
  if (matches('HEAD')) {
    if (mainTip !== undefined) {
      lines.push(`${mainTip} HEAD${symrefs ? ' symref-target:refs/heads/main' : ''}`);
    } else if (unborn) {
      lines.push(`unborn HEAD symref-target:refs/heads/main`);
    }
  }
  const refs = [...repo.refs.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1));
  for (const [ref, oid] of refs) {
    if (!matches(ref)) continue;
    let line = `${oid} ${ref}`;
    if (peel && ref.startsWith('refs/tags/')) {
      const obj = repo.objects.get(oid);
      if (obj && obj.type === 'tag') {
        const tag = parseTag(obj.data);
        if (isOid(tag.object)) line += ` peeled:${tag.object}`;
      }
    }
    lines.push(line);
  }
  const parts = lines.map((l) => pktLine(l + '\n'));
  parts.push(FLUSH);
  return Buffer.concat(parts);
}
function fetchV2Response(repo: Repo, args: string[]): Buffer {
  // Pack contents depend only on the args and the object graph; objects are only
  // ever added, so the object count in the key makes any graph change a miss.
  return cachedResponse(`fetch2|${repo.id}|${repo.objects.size}|${args.join('\n')}`, () => buildFetchV2Response(repo, args));
}
function buildFetchV2Response(repo: Repo, args: string[]): Buffer {
  const wants: string[] = [];
  const haves: string[] = [];
  const oldShallow: string[] = [];
  let depth: number | null = null;
  for (const a of args) {
    if (a.startsWith('want ')) wants.push(a.slice(5).trim());
    else if (a.startsWith('have ')) haves.push(a.slice(5).trim());
    else if (a.startsWith('shallow ')) oldShallow.push(a.slice(8).trim());
    else if (a.startsWith('deepen ')) {
      const n = Number(a.slice(7).trim());
      if (Number.isFinite(n) && n >= 0) depth = Math.floor(n);
    }
  }
  const plan = planFetch(repo, wants, haves, depth, oldShallow);
  const parts: Buffer[] = [];
  parts.push(pktLine('acknowledgments\n'));
  if (plan.nak) parts.push(pktLine('NAK\n'));
  else for (const ack of plan.acks) parts.push(pktLine(`ACK ${ack}\n`));
  parts.push(pktLine('ready\n'));
  parts.push(FLUSH);
  if (plan.shallow.length > 0 || plan.unshallow.length > 0) {
    parts.push(pktLine('shallow-info\n'));
    for (const s of plan.shallow) parts.push(pktLine(`shallow ${s}\n`));
    for (const s of plan.unshallow) parts.push(pktLine(`unshallow ${s}\n`));
    parts.push(FLUSH);
  }
  if (plan.objects.length > 0) {
    parts.push(pktLine('packfile\n'));
    parts.push(sidebandPack(writePack(plan.objects)));
    parts.push(FLUSH);
  }
  return Buffer.concat(parts);
}
function fetchV0Response(repo: Repo, section1: string[], section2: string[]): Buffer {
  return cachedResponse(`fetch0|${repo.id}|${repo.objects.size}|${section1.join('\n')}#${section2.join('\n')}`, () => buildFetchV0Response(repo, section1, section2));
}
function buildFetchV0Response(repo: Repo, section1: string[], section2: string[]): Buffer {
  const wants: string[] = [];
  const oldShallow: string[] = [];
  let depth: number | null = null;
  for (const line of section1) {
    if (line.startsWith('want ')) wants.push(line.slice(5).split(' ')[0].trim());
    else if (line.startsWith('shallow ')) oldShallow.push(line.slice(8).trim());
    else if (line.startsWith('deepen ')) {
      const n = Number(line.slice(7).trim());
      if (Number.isFinite(n) && n >= 0) depth = Math.floor(n);
    }
  }
  const haves: string[] = [];
  for (const line of section2) {
    if (line.startsWith('have ')) haves.push(line.slice(5).trim());
  }
  const plan = planFetch(repo, wants, haves, depth, oldShallow);
  const parts: Buffer[] = [];
  if (plan.nak) parts.push(pktLine('NAK\n'));
  else for (const ack of plan.acks) parts.push(pktLine(`ACK ${ack}\n`));
  for (const s of plan.shallow) parts.push(pktLine(`shallow ${s}\n`));
  for (const s of plan.unshallow) parts.push(pktLine(`unshallow ${s}\n`));
  if (plan.objects.length > 0) parts.push(sidebandPack(writePack(plan.objects)));
  parts.push(FLUSH);
  return Buffer.concat(parts);
}
async function handleGit(req: IncomingMessage, res: ServerResponse, segments: string[], query: URLSearchParams, bodyBuf: Buffer): Promise<void> {
  const method = req.method ?? 'GET';
  const owner = segments[0];
  const repoName = segments[1].slice(0, -4); // strip '.git'
  const repo = getRepo(owner, repoName);
  if (repo === undefined) return sendError(res, 404, 'Not Found');
  const sub = segments.slice(2);

  // GET /{owner}/{repo}.git/info/refs?service=...
  if (method === 'GET' && sub.length === 2 && sub[0] === 'info' && sub[1] === 'refs') {
    const service = query.get('service');
    if (service === 'git-upload-pack') {
      const v2 = req.headers['git-protocol'] === 'version=2';
      if (v2) {
        // Constant: no refs, just capabilities.
        const body = cachedResponse('adv-v2-upload', () =>
          Buffer.concat([
            pktLine('# service=git-upload-pack\n'),
            FLUSH,
            pktLine('version 2\n'),
            pktLine('ls-refs=unborn\n'),
            pktLine('fetch=shallow\n'),
            pktLine(`agent=${AGENT}\n`),
            pktLine('object-format=sha1\n'),
            FLUSH,
          ]),
        );
        return sendGit(res, 200, 'application/x-git-upload-pack-advertisement', body);
      }
      const caps = `symref=HEAD:refs/heads/main side-band-64k thin-pack ofs-delta multi_ack shallow agent=${AGENT}`;
      const body = cachedResponse(`adv-v0-upload|${repo.id}|${refsKey(repo)}`, () =>
        Buffer.concat([pktLine('# service=git-upload-pack\n'), FLUSH, ...refAdvertisementLines(repo, caps), FLUSH]),
      );
      return sendGit(res, 200, 'application/x-git-upload-pack-advertisement', body);
    }
    if (service === 'git-receive-pack') {
      const caps = `symref=HEAD:refs/heads/main report-status report-status-v2 side-band-64k delete-refs ofs-delta agent=${AGENT}`;
      const body = cachedResponse(`adv-v0-receive|${repo.id}|${refsKey(repo)}`, () =>
        Buffer.concat([pktLine('# service=git-receive-pack\n'), FLUSH, ...refAdvertisementLines(repo, caps), FLUSH]),
      );
      return sendGit(res, 200, 'application/x-git-receive-pack-advertisement', body);
    }
    return sendError(res, 400, 'service parameter is required');
  }

  // POST git-upload-pack
  if (method === 'POST' && sub.length === 1 && sub[0] === 'git-upload-pack') {
    const v2 = req.headers['git-protocol'] === 'version=2';
    const { packets } = parsePktLines(bodyBuf, 0);
    const lines = packets.filter((p) => p.kind === 'data').map((p) => (p.data as Buffer).toString('utf8').replace(/\n$/, ''));
    if (lines.length === 0) return sendError(res, 400, 'empty request');
    if (v2) {
      const commandLine = lines[0];
      // Rebuild args from packets after the delim packet.
      const afterDelim: string[] = [];
      let seenDelim = false;
      for (const p of packets) {
        if (p.kind === 'delim') {
          seenDelim = true;
          continue;
        }
        if (p.kind === 'data' && seenDelim) afterDelim.push((p.data as Buffer).toString('utf8').replace(/\n$/, ''));
        if (p.kind === 'flush') break;
      }
      if (commandLine === 'command=ls-refs') {
        return sendGit(res, 200, 'application/x-git-upload-pack-result', lsRefsResponse(repo, afterDelim));
      }
      if (commandLine === 'command=fetch') {
        return sendGit(res, 200, 'application/x-git-upload-pack-result', fetchV2Response(repo, afterDelim));
      }
      return sendError(res, 400, 'unknown command');
    }
    // v0: two sections separated by flush packets.
    const sections: string[][] = [[], []];
    let sectionIdx = 0;
    for (const p of packets) {
      if (p.kind === 'flush') {
        sectionIdx++;
        if (sectionIdx > 1) break;
        continue;
      }
      if (p.kind === 'data' && sectionIdx < 2) sections[sectionIdx].push((p.data as Buffer).toString('utf8').replace(/\n$/, ''));
    }
    if (sections[0].length === 0 || !sections[0].some((l) => l.startsWith('want '))) {
      return sendError(res, 400, 'invalid request');
    }
    return sendGit(res, 200, 'application/x-git-upload-pack-result', fetchV0Response(repo, sections[0], sections[1]));
  }

  // POST git-receive-pack
  if (method === 'POST' && sub.length === 1 && sub[0] === 'git-receive-pack') {
    const { packets, offset } = parsePktLines(bodyBuf, 0);
    const commandLines: string[] = [];
    for (const p of packets) {
      if (p.kind === 'flush') break;
      if (p.kind === 'data') commandLines.push((p.data as Buffer).toString('utf8'));
    }
    if (commandLines.length === 0) return sendError(res, 400, 'invalid request');
    const packBuf = bodyBuf.subarray(offset);
    // A delete-only command list carries no pack at all.
    const parsed: ParsedPack = packBuf.length === 0 ? { objects: [], ok: true } : readPack(packBuf);
    if (!parsed.ok) return sendError(res, 400, 'invalid pack');
    for (const obj of parsed.objects) {
      const oid = hashObject(obj.type, obj.data);
      if (!repo.objects.has(oid)) repo.objects.set(oid, obj);
    }
    const results: string[] = ['unpack ok'];
    for (const raw of commandLines) {
      const nul = raw.indexOf('\0');
      const line = (nul >= 0 ? raw.slice(0, nul) : raw).trim();
      const parts = line.split(' ');
      if (parts.length < 3) {
        results.push(`ng ${parts[2] ?? ''} malformed command`);
        continue;
      }
      const [oldOid, newOid, ref] = parts;
      const current = repo.refs.get(ref);
      if (newOid === ZERO_OID) {
        // Delete.
        if (current === undefined) results.push(`ng ${ref} remote ref does not exist`);
        else if (oldOid !== current) results.push(`ng ${ref} non-fast-forward`);
        else {
          repo.refs.delete(ref);
          results.push(`ok ${ref}`);
        }
        continue;
      }
      if (!repo.objects.has(newOid)) {
        results.push(`ng ${ref} unpack failed`);
        continue;
      }
      if (oldOid === ZERO_OID) {
        if (current !== undefined) results.push(`ng ${ref} non-fast-forward`);
        else {
          repo.refs.set(ref, newOid);
          results.push(`ok ${ref}`);
        }
        continue;
      }
      if (current === undefined) {
        results.push(`ng ${ref} non-fast-forward`);
        continue;
      }
      if (oldOid !== current) {
        results.push(`ng ${ref} non-fast-forward`);
        continue;
      }
      if (newOid === oldOid) {
        results.push(`ok ${ref}`);
        continue;
      }
      if (!isAncestor(repo, oldOid, newOid)) {
        results.push(`ng ${ref} non-fast-forward`);
        continue;
      }
      repo.refs.set(ref, newOid);
      results.push(`ok ${ref}`);
    }
    const report = Buffer.concat(results.map((r) => pktLine(r + '\n')));
    const body = Buffer.concat([sidebandPack(report), FLUSH]);
    return sendGit(res, 200, 'application/x-git-receive-pack-result', body);
  }
  return sendError(res, 404, 'Not Found');
}

// ---------------------------------------------------------------- GraphQL v4
type GqlValue =
  | { kind: 'var'; name: string }
  | { kind: 'string'; value: string }
  | { kind: 'int'; value: number }
  | { kind: 'float'; value: number }
  | { kind: 'bool'; value: boolean }
  | { kind: 'null' }
  | { kind: 'enum'; value: string }
  | { kind: 'list'; values: GqlValue[] }
  | { kind: 'object'; fields: Array<{ name: string; value: GqlValue }> };
interface GqlField {
  alias: string | null;
  name: string;
  args: Array<{ name: string; value: GqlValue }>;
  selection: GqlField[] | null;
  inlineType: string | null;
}
interface GqlOperation {
  type: 'query' | 'mutation';
  name: string | null;
  varDefs: Array<{ name: string; defaultValue: GqlValue | null }>;
  selection: GqlField[];
}
type Token =
  | { kind: 'name'; value: string }
  | { kind: 'int'; value: string }
  | { kind: 'float'; value: string }
  | { kind: 'string'; value: string }
  | { kind: 'punct'; value: string }
  | { kind: 'ellipsis' };
function tokenizeGql(src: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    if (c === ' ' || c === '\t' || c === '\n' || c === '\r' || c === ',') {
      i++;
      continue;
    }
    if (c === '#') {
      while (i < src.length && src[i] !== '\n') i++;
      continue;
    }
    if (c === '.' && src.slice(i, i + 3) === '...') {
      tokens.push({ kind: 'ellipsis' });
      i += 3;
      continue;
    }
    if ('{}()[]:!=$=@'.includes(c)) {
      tokens.push({ kind: 'punct', value: c });
      i++;
      continue;
    }
    if (c === '"') {
      let j = i + 1;
      let out = '';
      while (j < src.length && src[j] !== '"') {
        if (src[j] === '\\' && j + 1 < src.length) {
          const esc = src[j + 1];
          out += esc === 'n' ? '\n' : esc === 't' ? '\t' : esc === 'r' ? '\r' : esc === '"' ? '"' : esc === '\\' ? '\\' : esc;
          j += 2;
        } else {
          out += src[j];
          j++;
        }
      }
      tokens.push({ kind: 'string', value: out });
      i = j + 1;
      continue;
    }
    if (/[0-9-]/.test(c)) {
      let j = i;
      if (src[j] === '-') j++;
      while (j < src.length && /[0-9]/.test(src[j])) j++;
      let isFloat = false;
      if (src[j] === '.') {
        isFloat = true;
        j++;
        while (j < src.length && /[0-9]/.test(src[j])) j++;
      }
      if (src[j] === 'e' || src[j] === 'E') {
        isFloat = true;
        j++;
        if (src[j] === '+' || src[j] === '-') j++;
        while (j < src.length && /[0-9]/.test(src[j])) j++;
      }
      tokens.push(isFloat ? { kind: 'float', value: src.slice(i, j) } : { kind: 'int', value: src.slice(i, j) });
      i = j;
      continue;
    }
    if (/[_A-Za-z]/.test(c)) {
      let j = i;
      while (j < src.length && /[_A-Za-z0-9]/.test(src[j])) j++;
      tokens.push({ kind: 'name', value: src.slice(i, j) });
      i = j;
      continue;
    }
    throw new Error(`Unexpected character ${c}`);
  }
  return tokens;
}
class GqlParser {
  private pos = 0;
  private readonly tokens: Token[];
  constructor(tokens: Token[]) {
    this.tokens = tokens;
  }
  peek(): Token | undefined {
    return this.tokens[this.pos];
  }
  next(): Token {
    const t = this.tokens[this.pos];
    if (t === undefined) throw new Error('Unexpected end of document');
    this.pos++;
    return t;
  }
  expectPunct(value: string): void {
    const t = this.next();
    if (t.kind !== 'punct' || t.value !== value) throw new Error(`Expected ${value}`);
  }
  expectName(value?: string): string {
    const t = this.next();
    if (t.kind !== 'name') throw new Error('Expected name');
    if (value !== undefined && t.value !== value) throw new Error(`Expected ${value}`);
    return t.value;
  }
  parseDocument(): GqlOperation {
    const t = this.peek();
    if (t === undefined) throw new Error('Empty document');
    if (t.kind === 'punct' && t.value === '{') {
      return { type: 'query', name: null, varDefs: [], selection: this.parseSelectionSet() };
    }
    const type = this.expectName();
    if (type !== 'query' && type !== 'mutation' && type !== 'subscription') throw new Error(`Unknown operation ${type}`);
    let name: string | null = null;
    const next = this.peek();
    if (next !== undefined && next.kind === 'name') name = this.next().value as string;
    const varDefs: Array<{ name: string; defaultValue: GqlValue | null }> = [];
    const afterName = this.peek();
    if (afterName !== undefined && afterName.kind === 'punct' && afterName.value === '(') {
      this.next();
      while (true) {
        const p = this.peek();
        if (p === undefined) throw new Error('Unexpected end in variable definitions');
        if (p.kind === 'punct' && p.value === ')') {
          this.next();
          break;
        }
        this.expectPunct('$');
        const varName = this.expectName();
        this.expectPunct(':');
        // Type: name, possibly wrapped in [ ] and !. Skip it.
        this.skipType();
        let defaultValue: GqlValue | null = null;
        const maybeEq = this.peek();
        if (maybeEq !== undefined && maybeEq.kind === 'punct' && maybeEq.value === '=') {
          this.next();
          defaultValue = this.parseValue();
        }
        varDefs.push({ name: varName, defaultValue });
      }
    }
    return { type: type as 'query' | 'mutation', name, varDefs, selection: this.parseSelectionSet() };
  }
  skipType(): void {
    const t = this.peek();
    if (t === undefined) throw new Error('Unexpected end in type');
    if (t.kind === 'punct' && t.value === '[') {
      this.next();
      this.skipType();
      this.expectPunct(']');
    } else {
      this.expectName();
    }
    const bang = this.peek();
    if (bang !== undefined && bang.kind === 'punct' && bang.value === '!') this.next();
  }
  parseSelectionSet(): GqlField[] {
    this.expectPunct('{');
    const fields: GqlField[] = [];
    while (true) {
      const t = this.peek();
      if (t === undefined) throw new Error('Unexpected end in selection set');
      if (t.kind === 'punct' && t.value === '}') {
        this.next();
        break;
      }
      fields.push(this.parseField());
    }
    return fields;
  }
  parseField(): GqlField {
    const t = this.peek();
    if (t !== undefined && t.kind === 'ellipsis') {
      this.next();
      let inlineType: string | null = null;
      const on = this.peek();
      if (on !== undefined && on.kind === 'name' && on.value === 'on') {
        this.next();
        inlineType = this.expectName();
      }
      const selection = this.parseSelectionSet();
      return { alias: null, name: '', args: [], selection, inlineType };
    }
    let name = this.expectName();
    let alias: string | null = null;
    const colon = this.peek();
    if (colon !== undefined && colon.kind === 'punct' && colon.value === ':') {
      this.next();
      alias = name;
      name = this.expectName();
    }
    const args: Array<{ name: string; value: GqlValue }> = [];
    const paren = this.peek();
    if (paren !== undefined && paren.kind === 'punct' && paren.value === '(') {
      this.next();
      while (true) {
        const p = this.peek();
        if (p === undefined) throw new Error('Unexpected end in arguments');
        if (p.kind === 'punct' && p.value === ')') {
          this.next();
          break;
        }
        const argName = this.expectName();
        this.expectPunct(':');
        args.push({ name: argName, value: this.parseValue() });
      }
    }
    let selection: GqlField[] | null = null;
    const brace = this.peek();
    if (brace !== undefined && brace.kind === 'punct' && brace.value === '{') {
      selection = this.parseSelectionSet();
    }
    return { alias, name, args, selection, inlineType: null };
  }
  parseValue(): GqlValue {
    const t = this.next();
    if (t.kind === 'punct' && t.value === '$') {
      return { kind: 'var', name: this.expectName() };
    }
    if (t.kind === 'punct' && t.value === '[') {
      const values: GqlValue[] = [];
      while (true) {
        const p = this.peek();
        if (p === undefined) throw new Error('Unexpected end in list');
        if (p.kind === 'punct' && p.value === ']') {
          this.next();
          break;
        }
        values.push(this.parseValue());
      }
      return { kind: 'list', values };
    }
    if (t.kind === 'punct' && t.value === '{') {
      const fields: Array<{ name: string; value: GqlValue }> = [];
      while (true) {
        const p = this.peek();
        if (p === undefined) throw new Error('Unexpected end in object');
        if (p.kind === 'punct' && p.value === '}') {
          this.next();
          break;
        }
        const name = this.expectName();
        this.expectPunct(':');
        fields.push({ name, value: this.parseValue() });
      }
      return { kind: 'object', fields };
    }
    if (t.kind === 'string') return { kind: 'string', value: t.value };
    if (t.kind === 'int') return { kind: 'int', value: Number(t.value) };
    if (t.kind === 'float') return { kind: 'float', value: Number(t.value) };
    if (t.kind === 'name') {
      if (t.value === 'true') return { kind: 'bool', value: true };
      if (t.value === 'false') return { kind: 'bool', value: false };
      if (t.value === 'null') return { kind: 'null' };
      return { kind: 'enum', value: t.value };
    }
    throw new Error('Unexpected value');
  }
}
function resolveGqlValue(v: GqlValue, variables: Record<string, unknown>): unknown {
  switch (v.kind) {
    case 'var':
      return variables[v.name] ?? null;
    case 'string':
      return v.value;
    case 'int':
    case 'float':
      return v.value;
    case 'bool':
      return v.value;
    case 'null':
      return null;
    case 'enum':
      return v.value;
    case 'list':
      return v.values.map((x) => resolveGqlValue(x, variables));
    case 'object': {
      const out: Record<string, unknown> = {};
      for (const f of v.fields) out[f.name] = resolveGqlValue(f.value, variables);
      return out;
    }
  }
}
function argMap(field: GqlField, variables: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const a of field.args) out[a.name] = resolveGqlValue(a.value, variables);
  return out;
}
// ---------------------------------------------------------------- GraphQL schema
const TYPE_FIELDS: Record<string, string[]> = {
  Issue: ['id', 'databaseId', 'number', 'title', 'body', 'state', 'author', 'createdAt', 'updatedAt', 'labels', 'comments', 'url', 'repository'],
  PullRequest: ['id', 'databaseId', 'number', 'title', 'body', 'state', 'merged', 'mergeable', 'headRefName', 'baseRefName', 'files', 'headRef', 'baseRef', 'author', 'createdAt', 'updatedAt', 'mergedAt', 'mergeCommit', 'url'],
  Repository: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest', 'description', 'private', 'createdAt', 'updatedAt', 'url'],
  User: ['id', 'login', 'name', 'email', 'url'],
  IssueConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  PullRequestConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  PullRequestChangedFileConnection: ['nodes', 'pageInfo', 'totalCount'],
  PageInfo: ['hasNextPage', 'hasPreviousPage', 'startCursor', 'endCursor'],
  Ref: ['name'],
  PullRequestChangedFile: ['path'],
  Comment: ['id', 'body', 'author'],
  CommentEdge: ['node', 'cursor'],
  Query: ['viewer', 'repository', 'node', '__type', '__schema'],
  Mutation: ['createIssue', 'closeIssue', 'createPullRequest', 'mergePullRequest', 'addComment'],
  __Type: ['name', 'kind', 'fields', 'enumValues', 'description'],
  __Field: ['name', 'description', 'args'],
  __EnumValue: ['name', 'description'],
  __Schema: ['queryType', 'mutationType', 'types'],
};
const ENUM_VALUES: Record<string, string[]> = {
  SearchType: ['ISSUE', 'PULL_REQUEST', 'REPOSITORY', 'USER', 'DISCUSSION', 'COMMIT', 'MILESTONE', 'ORGANIZATION'],
};
type GqlNode = { __typename: string; [key: string]: unknown };
function userNode(login: string): GqlNode {
  return { __typename: 'User', login, id: b64encode(`user:${login === VIEWER_LOGIN ? VIEWER_ID : 0}`), name: login === VIEWER_LOGIN ? VIEWER_NAME : login, email: login === VIEWER_LOGIN ? VIEWER_EMAIL : `${login}@example.invalid`, url: `https://github.com/${login}` };
}
function repoNode(repo: Repo): GqlNode {
  return { __typename: 'Repository', repo };
}
function issueNode(repo: Repo, issue: Issue): GqlNode {
  return { __typename: 'Issue', repo, issue, number: issue.number };
}
function pullNode(repo: Repo, pull: Pull): GqlNode {
  return { __typename: 'PullRequest', repo, pull, number: pull.number };
}
function cursorFor(number: number): string {
  return b64encode(`cursor:${number}`);
}
function cursorNumber(cursor: string): number | null {
  try {
    const text = b64decode(cursor);
    if (!text.startsWith('cursor:')) return null;
    const n = Number(text.slice(7));
    return Number.isInteger(n) ? n : null;
  } catch {
    return null;
  }
}
function connectionFrom<T>(items: T[], first: number | undefined, after: string | undefined, numberOf: (x: T) => number): GqlNode {
  let start = 0;
  if (after !== undefined && after !== null) {
    const n = cursorNumber(after as string);
    if (n !== null) {
      const idx = items.findIndex((x) => numberOf(x) === n);
      if (idx >= 0) start = idx + 1;
    }
  }
  const sliced = first !== undefined ? items.slice(start, start + first) : items.slice(start);
  const hasNextPage = start + sliced.length < items.length;
  const endCursor = sliced.length > 0 ? cursorFor(numberOf(sliced[sliced.length - 1])) : null;
  const startCursor = sliced.length > 0 ? cursorFor(numberOf(sliced[0])) : null;
  return {
    __typename: 'Connection',
    nodes: sliced,
    edges: sliced.map((x) => ({ __typename: 'Edge', node: x, cursor: cursorFor(numberOf(x)) })),
    totalCount: items.length,
    pageInfo: { __typename: 'PageInfo', hasNextPage, hasPreviousPage: start > 0, startCursor, endCursor },
  };
}
function resolveField(node: GqlNode, field: GqlField, variables: Record<string, unknown>): unknown {
  const args = argMap(field, variables);
  const type = node.__typename;
  if (type === 'Query') {
    if (field.name === 'viewer') return userNode(VIEWER_LOGIN);
    if (field.name === 'repository') {
      const repo = getRepo(String(args.owner ?? ''), String(args.name ?? ''));
      return repo === undefined ? null : repoNode(repo);
    }
    if (field.name === 'node') {
      const decoded = decodeGlobalId(String(args.id ?? ''));
      if (decoded === null) return null;
      const repo = getRepoById(decoded.repoId);
      if (repo === undefined) return null;
      if (decoded.kind === 'repo') return repoNode(repo);
      if (decoded.kind === 'issue') {
        const issue = repo.issues.find((i) => i.number === decoded.num);
        return issue === undefined ? null : issueNode(repo, issue);
      }
      if (decoded.kind === 'pr') {
        const pull = repo.pulls.find((p) => p.number === decoded.num);
        return pull === undefined ? null : pullNode(repo, pull);
      }
      return null;
    }
    if (field.name === '__type') {
      const name = String(args.name ?? '');
      if (TYPE_FIELDS[name] !== undefined) {
        return { __typename: '__Type', name, kind: 'OBJECT', fields: TYPE_FIELDS[name].map((f) => ({ __typename: '__Field', name: f })), enumValues: null };
      }
      if (ENUM_VALUES[name] !== undefined) {
        return { __typename: '__Type', name, kind: 'ENUM', fields: null, enumValues: ENUM_VALUES[name].map((f) => ({ __typename: '__EnumValue', name: f })) };
      }
      return null;
    }
    if (field.name === '__schema') {
      return { __typename: '__Schema', queryType: { __typename: '__Type', name: 'Query', kind: 'OBJECT' }, mutationType: { __typename: '__Type', name: 'Mutation', kind: 'OBJECT' }, types: [] };
    }
    throw new Error(`Unknown Query field ${field.name}`);
  }
  if (type === 'Mutation') {
    if (field.name === 'createIssue') {
      const input = asRecord(args.input);
      const decoded = decodeGlobalId(String(input.repositoryId ?? ''));
      if (decoded === null || decoded.kind !== 'repo') throw new Error('Repository not found');
      const repo = getRepoById(decoded.repoId);
      if (repo === undefined) throw new Error('Repository not found');
      const issue = createIssueInternal(repo, String(input.title ?? ''), String(input.body ?? ''), []);
      return { __typename: 'CreateIssuePayload', issue: issueNode(repo, issue) };
    }
    if (field.name === 'closeIssue') {
      const input = asRecord(args.input);
      const decoded = decodeGlobalId(String(input.issueId ?? ''));
      if (decoded === null || decoded.kind !== 'issue') throw new Error('Issue not found');
      const repo = getRepoById(decoded.repoId);
      const issue = repo?.issues.find((i) => i.number === decoded.num);
      if (repo === undefined || issue === undefined) throw new Error('Issue not found');
      issue.state = 'closed';
      repo.viewVersion++;
      return { __typename: 'CloseIssuePayload', issue: issueNode(repo, issue) };
    }
    if (field.name === 'createPullRequest') {
      const input = asRecord(args.input);
      const decoded = decodeGlobalId(String(input.repositoryId ?? ''));
      if (decoded === null || decoded.kind !== 'repo') throw new Error('Repository not found');
      const repo = getRepoById(decoded.repoId);
      if (repo === undefined) throw new Error('Repository not found');
      const headRef = String(input.headRefName ?? '');
      const baseRef = String(input.baseRefName ?? '');
      const headSha = repo.refs.get(`refs/heads/${headRef}`);
      const baseSha = repo.refs.get(`refs/heads/${baseRef}`);
      if (headSha === undefined || baseSha === undefined) throw new Error('Head or base does not exist');
      const dup = repo.pulls.find((p) => p.state === 'open' && p.headRef === headRef && p.baseRef === baseRef);
      if (dup !== undefined) throw new Error('A pull request already exists for this head and base');
      const pull = createPullInternal(repo, String(input.title ?? ''), String(input.body ?? ''), headRef, headSha, baseRef, baseSha);
      return { __typename: 'CreatePullRequestPayload', pullRequest: pullNode(repo, pull) };
    }
    if (field.name === 'mergePullRequest') {
      const input = asRecord(args.input);
      const decoded = decodeGlobalId(String(input.pullRequestId ?? ''));
      if (decoded === null || decoded.kind !== 'pr') throw new Error('Pull request not found');
      const repo = getRepoById(decoded.repoId);
      const pull = repo?.pulls.find((p) => p.number === decoded.num);
      if (repo === undefined || pull === undefined) throw new Error('Pull request not found');
      if (pull.merged || pull.state === 'closed') throw new Error('Pull request is already merged or closed');
      if (hasMergeConflict(repo, pull.baseSha, pull.headSha)) throw new Error('Merge conflict');
      const headTree = commitTree(repo, pull.headSha);
      const message = `Merge pull request #${pull.number} from ${repo.owner}/${pull.headRef}`;
      const built = buildCommit(headTree ?? putObject(repo, 'tree', Buffer.alloc(0)), [pull.baseSha], message);
      repo.objects.set(built.oid, { type: 'commit', data: built.data });
      repo.refs.set(`refs/heads/${pull.baseRef}`, built.oid);
      pull.merged = true;
      pull.state = 'closed';
      pull.mergedAt = FIXED_DATE;
      pull.mergeCommitSha = built.oid;
      return { __typename: 'MergePullRequestPayload', pullRequest: pullNode(repo, pull) };
    }
    if (field.name === 'addComment') {
      const input = asRecord(args.input);
      const decoded = decodeGlobalId(String(input.subjectId ?? ''));
      if (decoded === null || decoded.kind !== 'issue') throw new Error('Subject not found');
      const repo = getRepoById(decoded.repoId);
      const issue = repo?.issues.find((i) => i.number === decoded.num);
      if (repo === undefined || issue === undefined) throw new Error('Issue not found');
      const comment: IssueComment = { id: repo.nextCommentId++, body: String(input.body ?? ''), user: VIEWER_LOGIN };
      const list = repo.comments.get(issue.number) ?? [];
      list.push(comment);
      repo.comments.set(issue.number, list);
      repo.viewVersion++;
      return {
        __typename: 'AddCommentPayload',
        commentEdge: { __typename: 'CommentEdge', node: { __typename: 'Comment', id: commentGlobalId(repo, comment), body: comment.body }, cursor: cursorFor(comment.id) },
      };
    }
    throw new Error(`Unknown Mutation field ${field.name}`);
  }
  if (type === 'User') {
    const login = String(node.login ?? '');
    if (field.name === 'login') return login;
    if (field.name === 'id') return String(node.id ?? '');
    if (field.name === 'name') return String(node.name ?? '');
    if (field.name === 'email') return String(node.email ?? '');
    if (field.name === 'url') return String(node.url ?? '');
    throw new Error(`Unknown User field ${field.name}`);
  }
  if (type === 'Repository') {
    const repo = node.repo as Repo;
    switch (field.name) {
      case 'id':
        return repoGlobalId(repo);
      case 'databaseId':
        return repo.id;
      case 'name':
        return repo.name;
      case 'nameWithOwner':
        return fullName(repo.owner, repo.name);
      case 'owner':
        return userNode(repo.owner);
      case 'defaultBranchRef': {
        const sha = repo.refs.get(`refs/heads/${repo.defaultBranch}`);
        return sha === undefined ? null : { __typename: 'Ref', name: repo.defaultBranch };
      }
      case 'viewerPermission':
        return 'ADMIN';
      case 'hasIssuesEnabled':
        return true;
      case 'description':
        return repo.description;
      case 'private':
        return repo.isPrivate;
      case 'createdAt':
      case 'updatedAt':
        return FIXED_DATE;
      case 'url':
        return `https://github.com/${repo.owner}/${repo.name}`;
      case 'issue': {
        const issue = repo.issues.find((i) => i.number === Number(args.number ?? -1));
        return issue === undefined ? null : issueNode(repo, issue);
      }
      case 'issues': {
        let list = [...repo.issues];
        const states = Array.isArray(args.states) ? (args.states as string[]) : undefined;
        if (states !== undefined) {
          const want = new Set(states.map((s) => s.toLowerCase()));
          list = list.filter((i) => want.has(i.state));
        }
        const orderBy = asRecord(args.orderBy);
        const direction = String(orderBy.direction ?? 'ASC');
        list.sort((a, b) => (direction === 'DESC' ? b.seq - a.seq : a.seq - b.seq));
        const nodes = list.map((i) => issueNode(repo, i));
        const conn = connectionFrom(nodes, args.first as number | undefined, args.after as string | undefined, (n) => Number(n.number ?? 0));
        conn.__typename = 'IssueConnection';
        return conn;
      }
      case 'pullRequest': {
        const pull = repo.pulls.find((p) => p.number === Number(args.number ?? -1));
        return pull === undefined ? null : pullNode(repo, pull);
      }
      case 'pullRequests': {
        let list = [...repo.pulls];
        const states = Array.isArray(args.states) ? (args.states as string[]) : undefined;
        if (states !== undefined) {
          const want = new Set(states.map((s) => (s === 'MERGED' ? 'closed' : s.toLowerCase())));
          list = list.filter((p) => {
            const st = p.merged ? 'MERGED' : p.state.toUpperCase();
            return want.has(st) || want.has(p.state);
          });
        }
        const orderBy = asRecord(args.orderBy);
        const direction = String(orderBy.direction ?? 'ASC');
        list.sort((a, b) => (direction === 'DESC' ? b.seq - a.seq : a.seq - b.seq));
        const nodes = list.map((p) => pullNode(repo, p));
        const conn = connectionFrom(nodes, args.first as number | undefined, args.after as string | undefined, (n) => Number(n.number ?? 0));
        conn.__typename = 'PullRequestConnection';
        return conn;
      }
      default:
        throw new Error(`Unknown Repository field ${field.name}`);
    }
  }
  if (type === 'Issue') {
    const repo = node.repo as Repo;
    const issue = node.issue as Issue;
    switch (field.name) {
      case 'id':
        return issueGlobalId(repo, issue);
      case 'databaseId':
        return issue.id;
      case 'number':
        return issue.number;
      case 'title':
        return issue.title;
      case 'body':
        return issue.body;
      case 'state':
        return issue.state.toUpperCase();
      case 'author':
        return userNode(issue.user);
      case 'createdAt':
      case 'updatedAt':
        return FIXED_DATE;
      case 'url':
        return `https://github.com/${repo.owner}/${repo.name}/issues/${issue.number}`;
      case 'repository':
        return repoNode(repo);
      default:
        throw new Error(`Unknown Issue field ${field.name}`);
    }
  }
  if (type === 'PullRequest') {
    const repo = node.repo as Repo;
    const pull = node.pull as Pull;
    switch (field.name) {
      case 'id':
        return pullGlobalId(repo, pull);
      case 'databaseId':
        return pull.id;
      case 'number':
        return pull.number;
      case 'title':
        return pull.title;
      case 'body':
        return pull.body;
      case 'state':
        return pull.merged ? 'MERGED' : pull.state.toUpperCase();
      case 'merged':
        return pull.merged;
      case 'mergeable':
        return pull.merged ? 'MERGED' : hasMergeConflict(repo, pull.baseSha, pull.headSha) ? 'CONFLICTING' : 'MERGEABLE';
      case 'headRefName':
        return pull.headRef;
      case 'baseRefName':
        return pull.baseRef;
      case 'headRef':
        return { __typename: 'Ref', name: pull.headRef };
      case 'baseRef':
        return { __typename: 'Ref', name: pull.baseRef };
      case 'author':
        return userNode(repo.owner);
      case 'createdAt':
      case 'updatedAt':
        return FIXED_DATE;
      case 'mergedAt':
        return pull.mergedAt;
      case 'url':
        return `https://github.com/${repo.owner}/${repo.name}/pull/${pull.number}`;
      case 'files': {
        const baseTree = commitTree(repo, pull.baseSha);
        const headTree = commitTree(repo, pull.headSha);
        const files = diffTrees(repo, baseTree, headTree).map((f) => ({ __typename: 'PullRequestChangedFile', path: f.filename }));
        const conn = connectionFrom(files, args.first as number | undefined, args.after as string | undefined, (f) => files.indexOf(f) + 1);
        conn.__typename = 'PullRequestChangedFileConnection';
        return conn;
      }
      default:
        throw new Error(`Unknown PullRequest field ${field.name}`);
    }
  }
  if (type === 'IssueConnection' || type === 'PullRequestConnection' || type === 'PullRequestChangedFileConnection' || type === 'Connection') {
    if (field.name === 'nodes') return (node.nodes as unknown[]) ?? [];
    if (field.name === 'edges') return (node.edges as unknown[]) ?? [];
    if (field.name === 'pageInfo') return node.pageInfo as GqlNode;
    if (field.name === 'totalCount') return (node.totalCount as number) ?? 0;
    throw new Error(`Unknown connection field ${field.name}`);
  }
  if (type === 'PageInfo') {
    const pageInfo = node as unknown as { hasNextPage: boolean; hasPreviousPage: boolean; startCursor: string | null; endCursor: string | null };
    if (field.name === 'hasNextPage') return pageInfo.hasNextPage;
    if (field.name === 'hasPreviousPage') return pageInfo.hasPreviousPage;
    if (field.name === 'startCursor') return pageInfo.startCursor;
    if (field.name === 'endCursor') return pageInfo.endCursor;
    throw new Error(`Unknown PageInfo field ${field.name}`);
  }
  if (type === 'Ref') {
    if (field.name === 'name') return String(node.name ?? '');
    throw new Error(`Unknown Ref field ${field.name}`);
  }
  if (type === 'PullRequestChangedFile') {
    if (field.name === 'path') return String(node.path ?? '');
    throw new Error(`Unknown PullRequestChangedFile field ${field.name}`);
  }
  if (type === 'Comment') {
    if (field.name === 'id') return String(node.id ?? '');
    if (field.name === 'body') return String(node.body ?? '');
    if (field.name === 'author') return userNode(VIEWER_LOGIN);
    throw new Error(`Unknown Comment field ${field.name}`);
  }
  if (type === 'CommentEdge') {
    if (field.name === 'node') return node.node as GqlNode;
    if (field.name === 'cursor') return String(node.cursor ?? '');
    throw new Error(`Unknown CommentEdge field ${field.name}`);
  }
  if (type === '__Type') {
    if (field.name === 'name') return String(node.name ?? '');
    if (field.name === 'kind') return String(node.kind ?? '');
    if (field.name === 'fields') return (node.fields as unknown) ?? null;
    if (field.name === 'enumValues') return (node.enumValues as unknown) ?? null;
    if (field.name === 'description') return null;
    throw new Error(`Unknown __Type field ${field.name}`);
  }
  if (type === '__Field' || type === '__EnumValue') {
    if (field.name === 'name') return String(node.name ?? '');
    if (field.name === 'description') return null;
    if (field.name === 'args') return [];
    throw new Error(`Unknown introspection field ${field.name}`);
  }
  if (type === '__Schema') {
    if (field.name === 'queryType') return node.queryType as GqlNode;
    if (field.name === 'mutationType') return node.mutationType as GqlNode;
    if (field.name === 'types') return (node.types as unknown[]) ?? [];
    throw new Error(`Unknown __Schema field ${field.name}`);
  }
  // Payload wrappers (createIssue, closeIssue, ...): passthrough fields.
  if (field.name === 'issue' || field.name === 'pullRequest' || field.name === 'commentEdge') {
    return node[field.name] as GqlNode;
  }
  throw new Error(`Cannot resolve field ${field.name} on ${type}`);
}
function executeSelection(node: GqlNode, selection: GqlField[], variables: Record<string, unknown>, errors: Array<{ message: string }>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const field of selection) {
    if (field.name === '') {
      // Inline fragment.
      if (field.inlineType === null || field.inlineType === node.__typename) {
        const sub = executeSelection(node, field.selection ?? [], variables, errors);
        Object.assign(out, sub);
      }
      continue;
    }
    const key = field.alias ?? field.name;
    const allowed = TYPE_FIELDS[node.__typename];
    if (field.name !== '__typename' && allowed !== undefined && !allowed.includes(field.name)) {
      errors.push({ message: `Cannot query field "${field.name}" on type "${node.__typename}".` });
      out[key] = null;
      continue;
    }
    if (field.name === '__typename') {
      out[key] = node.__typename;
      continue;
    }
    let value: unknown;
    try {
      value = resolveField(node, field, variables);
    } catch (e) {
      errors.push({ message: e instanceof Error ? e.message : String(e) });
      out[key] = null;
      continue;
    }
    if (field.selection !== null && value !== null && value !== undefined) {
      if (Array.isArray(value)) {
        out[key] = value.map((item) => {
          if (item !== null && typeof item === 'object' && '__typename' in (item as Record<string, unknown>)) {
            return executeSelection(item as GqlNode, field.selection as GqlField[], variables, errors);
          }
          return item;
        });
      } else if (typeof value === 'object' && '__typename' in (value as Record<string, unknown>)) {
        out[key] = executeSelection(value as GqlNode, field.selection as GqlField[], variables, errors);
      } else {
        out[key] = value;
      }
    } else {
      out[key] = value ?? null;
    }
  }
  return out;
}
function executeGraphQL(query: string, variables: Record<string, unknown>): { data: unknown; errors?: Array<{ message: string }> } {
  try {
    const parser = new GqlParser(tokenizeGql(query));
    const op = parser.parseDocument();
    const rootType = op.type === 'mutation' ? 'Mutation' : 'Query';
    const root: GqlNode = { __typename: rootType };
    const errors: Array<{ message: string }> = [];
    const data = executeSelection(root, op.selection, variables, errors);
    if (errors.length > 0) return { data: null, errors };
    return { data };
  } catch (e) {
    return { data: null, errors: [{ message: e instanceof Error ? e.message : String(e) }] };
  }
}
async function handleGraphQL(req: IncomingMessage, res: ServerResponse, bodyBuf: Buffer): Promise<void> {
  const parsed = parseJsonBody(bodyBuf);
  if (!parsed.ok) {
    return sendJson(res, 400, { errors: [{ message: 'Problems parsing JSON' }] });
  }
  const runOne = (entry: unknown): Record<string, unknown> => {
    const rec = asRecord(entry);
    const query = asString(rec.query);
    if (query === undefined) return { data: null, errors: [{ message: 'Must provide query string.' }] };
    const variables = asRecord(rec.variables);
    return executeGraphQL(query, variables);
  };
  if (Array.isArray(parsed.value)) {
    return sendJson(res, 200, parsed.value.map(runOne));
  }
  return sendJson(res, 200, runOne(parsed.value));
}

// ---------------------------------------------------------------- MCP
const MCP_SUPPORTED_VERSIONS = ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];
const MCP_TOOLS: Array<Record<string, unknown>> = [
  {
    name: 'create_repo',
    description: 'Create a new repository owned by the authenticated user.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Repository name' },
        description: { type: 'string', description: 'Repository description' },
        private: { type: 'boolean', description: 'Whether the repository is private' },
      },
      required: ['name'],
      additionalProperties: false,
    },
  },
  {
    name: 'get_repo',
    description: 'Get a repository by owner and name.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
      },
      required: ['owner', 'repo'],
      additionalProperties: false,
    },
  },
  {
    name: 'create_issue',
    description: 'Create an issue in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        title: { type: 'string', description: 'Issue title' },
        body: { type: 'string', description: 'Issue body' },
      },
      required: ['owner', 'repo', 'title'],
      additionalProperties: false,
    },
  },
  {
    name: 'list_issues',
    description: 'List issues in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        state: { type: 'string', description: 'Issue state: open, closed, or all' },
      },
      required: ['owner', 'repo'],
      additionalProperties: false,
    },
  },
  {
    name: 'create_pull_request',
    description: 'Create a pull request in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        title: { type: 'string', description: 'Pull request title' },
        head: { type: 'string', description: 'Head branch name' },
        base: { type: 'string', description: 'Base branch name' },
        body: { type: 'string', description: 'Pull request body' },
      },
      required: ['owner', 'repo', 'title', 'head', 'base'],
      additionalProperties: false,
    },
  },
  {
    name: 'merge_pull_request',
    description: 'Merge a pull request with a squash merge.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        pull_number: { type: 'number', description: 'Pull request number' },
      },
      required: ['owner', 'repo', 'pull_number'],
      additionalProperties: false,
    },
  },
  {
    name: 'get_issue',
    description: 'Get an issue by number.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        issue_number: { type: 'number', description: 'Issue number' },
      },
      required: ['owner', 'repo', 'issue_number'],
      additionalProperties: false,
    },
  },
  {
    name: 'list_pull_requests',
    description: 'List pull requests in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        state: { type: 'string', description: 'Pull request state: open, closed, or all' },
      },
      required: ['owner', 'repo'],
      additionalProperties: false,
    },
  },
];
function mcpResult(id: unknown, result: unknown): Record<string, unknown> {
  return { jsonrpc: '2.0', id, result };
}
function mcpError(id: unknown, code: number, message: string): Record<string, unknown> {
  return { jsonrpc: '2.0', id, error: { code, message } };
}
function mcpToolSuccess(payload: unknown): Record<string, unknown> {
  return { content: [{ type: 'text', text: JSON.stringify(payload) }], structuredContent: payload, isError: false };
}
function mcpToolFailure(message: string): Record<string, unknown> {
  return { content: [{ type: 'text', text: message }], structuredContent: { error: message }, isError: true };
}
function requiredArg(args: Record<string, unknown>, name: string): string | null {
  const v = args[name];
  return v === undefined || v === null || v === '' ? `Missing required argument: ${name}` : null;
}
function callMcpTool(name: string, args: Record<string, unknown>): Record<string, unknown> {
  const missing = (names: string[]): string | null => {
    for (const n of names) {
      const m = requiredArg(args, n);
      if (m !== null) return m;
    }
    return null;
  };
  if (name === 'create_repo') {
    const m = missing(['name']);
    if (m !== null) return mcpToolFailure(m);
    const repoName = String(args.name);
    if (getRepo(VIEWER_LOGIN, repoName) !== undefined) return mcpToolFailure('Repository already exists');
    const repo = createRepo(VIEWER_LOGIN, repoName, String(args.description ?? ''), args.private === true);
    return mcpToolSuccess(repoJson(repo));
  }
  if (name === 'get_repo') {
    const m = missing(['owner', 'repo']);
    if (m !== null) return mcpToolFailure(m);
    const repo = getRepo(String(args.owner), String(args.repo));
    if (repo === undefined) return mcpToolFailure('Repository not found');
    return mcpToolSuccess(repoJson(repo));
  }
  if (name === 'create_issue') {
    const m = missing(['owner', 'repo', 'title']);
    if (m !== null) return mcpToolFailure(m);
    const repo = getRepo(String(args.owner), String(args.repo));
    if (repo === undefined) return mcpToolFailure('Repository not found');
    const issue = createIssueInternal(repo, String(args.title), String(args.body ?? ''), []);
    return mcpToolSuccess(issueJson(repo, issue));
  }
  if (name === 'list_issues') {
    const m = missing(['owner', 'repo']);
    if (m !== null) return mcpToolFailure(m);
    const repo = getRepo(String(args.owner), String(args.repo));
    if (repo === undefined) return mcpToolFailure('Repository not found');
    const state = String(args.state ?? 'open').toLowerCase();
    let list = [...repo.issues];
    if (state === 'open') list = list.filter((i) => i.state === 'open');
    else if (state === 'closed') list = list.filter((i) => i.state === 'closed');
    list.sort((a, b) => b.seq - a.seq);
    const items = list.map((i) => issueJson(repo, i));
    return { content: [{ type: 'text', text: JSON.stringify(items) }], structuredContent: { issues: items }, isError: false };
  }
  if (name === 'create_pull_request') {
    const m = missing(['owner', 'repo', 'title', 'head', 'base']);
    if (m !== null) return mcpToolFailure(m);
    const repo = getRepo(String(args.owner), String(args.repo));
    if (repo === undefined) return mcpToolFailure('Repository not found');
    const headRef = stripBranchPrefix(String(args.head));
    const baseRef = stripBranchPrefix(String(args.base));
    const headSha = repo.refs.get(`refs/heads/${headRef}`);
    const baseSha = repo.refs.get(`refs/heads/${baseRef}`);
    if (headSha === undefined || baseSha === undefined) return mcpToolFailure('Head or base does not exist');
    const dup = repo.pulls.find((p) => p.state === 'open' && p.headRef === headRef && p.baseRef === baseRef);
    if (dup !== undefined) return mcpToolFailure('A pull request already exists for this head and base');
    const pull = createPullInternal(repo, String(args.title), String(args.body ?? ''), headRef, headSha, baseRef, baseSha);
    return mcpToolSuccess(pullJson(repo, pull));
  }
  if (name === 'merge_pull_request') {
    const m = missing(['owner', 'repo', 'pull_number']);
    if (m !== null) return mcpToolFailure(m);
    const repo = getRepo(String(args.owner), String(args.repo));
    if (repo === undefined) return mcpToolFailure('Repository not found');
    const pull = repo.pulls.find((p) => p.number === Number(args.pull_number));
    if (pull === undefined) return mcpToolFailure('Pull request not found');
    if (pull.merged || pull.state === 'closed') return mcpToolFailure('Pull request is already merged or closed');
    if (hasMergeConflict(repo, pull.baseSha, pull.headSha)) return mcpToolFailure('Merge conflict');
    const headTree = commitTree(repo, pull.headSha);
    const message = `Merge pull request #${pull.number} from ${repo.owner}/${pull.headRef}`;
    const built = buildCommit(headTree ?? putObject(repo, 'tree', Buffer.alloc(0)), [pull.baseSha], message);
    repo.objects.set(built.oid, { type: 'commit', data: built.data });
    repo.refs.set(`refs/heads/${pull.baseRef}`, built.oid);
    pull.merged = true;
    pull.state = 'closed';
    pull.mergedAt = FIXED_DATE;
    pull.mergeCommitSha = built.oid;
    return mcpToolSuccess({ merged: true, number: pull.number, sha: built.oid, state: 'closed' });
  }
  if (name === 'get_issue') {
    const m = missing(['owner', 'repo', 'issue_number']);
    if (m !== null) return mcpToolFailure(m);
    const repo = getRepo(String(args.owner), String(args.repo));
    if (repo === undefined) return mcpToolFailure('Repository not found');
    const issue = repo.issues.find((i) => i.number === Number(args.issue_number));
    if (issue === undefined) return mcpToolFailure('Issue not found');
    return mcpToolSuccess(issueJson(repo, issue));
  }
  if (name === 'list_pull_requests') {
    const m = missing(['owner', 'repo']);
    if (m !== null) return mcpToolFailure(m);
    const repo = getRepo(String(args.owner), String(args.repo));
    if (repo === undefined) return mcpToolFailure('Repository not found');
    const state = String(args.state ?? 'open').toLowerCase();
    let list = [...repo.pulls];
    if (state === 'open') list = list.filter((p) => p.state === 'open');
    else if (state === 'closed') list = list.filter((p) => p.state === 'closed');
    list.sort((a, b) => b.seq - a.seq);
    const items = list.map((p) => pullJson(repo, p));
    return { content: [{ type: 'text', text: JSON.stringify(items) }], structuredContent: { pull_requests: items }, isError: false };
  }
  return mcpToolFailure(`Unknown tool: ${name}`);
}
async function handleMcp(req: IncomingMessage, res: ServerResponse, bodyBuf: Buffer): Promise<void> {
  const method = req.method ?? 'GET';
  if (method === 'GET') return sendError(res, 405, 'Method not allowed');
  if (method !== 'POST') return sendError(res, 405, 'Method not allowed');
  // Parse early to recover the request id for the 401 envelope.
  let bodyValue: unknown = null;
  let bodyOk = true;
  try {
    bodyValue = bodyBuf.length === 0 ? null : JSON.parse(bodyBuf.toString('utf8'));
  } catch {
    bodyOk = false;
  }
  const reqId = bodyValue !== null && typeof bodyValue === 'object' && !Array.isArray(bodyValue)
    ? (bodyValue as Record<string, unknown>).id ?? null
    : null;
  if (!isAuthorized(req)) {
    res.writeHead(401, { 'content-type': 'application/json' });
    res.end(JSON.stringify(mcpError(reqId, -32001, 'Unauthorized')));
    return;
  }
  if (!bodyOk || bodyValue === null || typeof bodyValue !== 'object' || Array.isArray(bodyValue)) {
    res.writeHead(400, { 'content-type': 'application/json' });
    res.end(JSON.stringify(mcpError(null, -32700, 'Parse error')));
    return;
  }
  const body = bodyValue as Record<string, unknown>;
  const id = body.id ?? null;
  const methodName = asString(body.method);
  const params = asRecord(body.params);
  if (methodName === undefined) {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify(mcpError(id, -32600, 'Invalid Request')));
    return;
  }
  // Notifications (no id) get an empty 202.
  if (id === null || id === undefined) {
    res.writeHead(202);
    res.end();
    return;
  }
  const send = (payload: Record<string, unknown>): void => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify(payload));
  };
  if (methodName === 'server/discover') {
    return send(
      mcpResult(id, {
        supportedVersions: MCP_SUPPORTED_VERSIONS,
        capabilities: { tools: {} },
        serverInfo: { name: 'forge', version: VERSION },
        instructions: 'A GitHub-compatible git forge. Use the tools to manage repositories, issues and pull requests.',
        _meta: { 'io.modelcontextprotocol/serverInfo': { name: 'forge', version: VERSION } },
      }),
    );
  }
  if (methodName === 'initialize') {
    const requested = asString(params.protocolVersion);
    const negotiated = requested !== undefined && MCP_SUPPORTED_VERSIONS.includes(requested) ? requested : '2026-07-28';
    return send(
      mcpResult(id, {
        protocolVersion: negotiated,
        capabilities: { tools: {} },
        serverInfo: { name: 'forge', version: VERSION },
      }),
    );
  }
  if (methodName === 'ping') {
    return send(mcpResult(id, {}));
  }
  if (methodName === 'tools/list') {
    return send(mcpResult(id, { tools: MCP_TOOLS }));
  }
  if (methodName === 'tools/call') {
    const toolName = asString(params.name);
    if (toolName === undefined) return send(mcpError(id, -32602, 'Missing tool name'));
    const known = MCP_TOOLS.some((t) => t.name === toolName);
    if (!known) return send(mcpError(id, -32601, `Unknown tool: ${toolName}`));
    const result = callMcpTool(toolName, asRecord(params.arguments));
    return send(mcpResult(id, result));
  }
  return send(mcpError(id, -32601, `Method not found: ${methodName}`));
}

// ---------------------------------------------------------------- dispatcher
async function handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
  try {
    const method = req.method ?? 'GET';
    const rawUrl = req.url ?? '/';
    // Lean URL split: the suite sends clean absolute paths, so parse by hand
    // instead of paying for the URL constructor on every request. Fall back to
    // URL only for dot segments / fragments, which URL normalizes away.
    const qi = rawUrl.indexOf('?');
    const rawPath = qi < 0 ? rawUrl : rawUrl.slice(0, qi);
    const needsUrl =
      rawPath === '/.' ||
      rawPath === '/..' ||
      rawPath.includes('/./') ||
      rawPath.includes('/../') ||
      rawPath.endsWith('/.') ||
      rawPath.endsWith('/..') ||
      rawUrl.includes('#');
    let pathname: string;
    let query: URLSearchParams;
    if (needsUrl) {
      const url = new URL(rawUrl, 'http://127.0.0.1');
      pathname = url.pathname;
      query = url.searchParams;
    } else {
      pathname = rawPath;
      query = qi < 0 ? EMPTY_PARAMS : new URLSearchParams(rawUrl.slice(qi + 1));
    }
    if (pathname.length > 1 && pathname.endsWith('/')) pathname = pathname.slice(0, -1);
    const segments = pathname
      .split('/')
      .filter((s) => s.length > 0)
      .map((s) => {
        if (!s.includes('%')) return s;
        try {
          return decodeURIComponent(s);
        } catch {
          return s;
        }
      });
    // GETs here never carry a body (no content-length / transfer-encoding):
    // skip attaching body listeners and waiting for 'end' on every read.
    const clen = req.headers['content-length'];
    const bodyBuf =
      (method === 'GET' || method === 'HEAD') &&
      req.headers['transfer-encoding'] === undefined &&
      (clen === undefined || clen === '0')
        ? EMPTY_BODY
        : await readBody(req);

    // GET /healthz
    if (segments.length === 1 && segments[0] === 'healthz') {
      if (method !== 'GET') return sendError(res, 404, 'Not Found');
      return sendJson(res, 200, { ok: true });
    }
    // Git smart HTTP: /{owner}/{repo}.git/...
    if (segments.length >= 2 && segments[1].endsWith('.git')) {
      return handleGit(req, res, segments, query, bodyBuf);
    }
    // REST v3
    if (segments.length >= 2 && segments[0] === 'api' && segments[1] === 'v3') {
      if (!isAuthorized(req)) return sendError(res, 401, 'Requires authentication');
      return handleRest(req, res, segments, query, bodyBuf);
    }
    // GraphQL v4
    if (segments.length === 2 && segments[0] === 'api' && segments[1] === 'graphql') {
      if (method !== 'POST') return sendError(res, 404, 'Not Found');
      if (!isAuthorized(req)) return sendError(res, 401, 'Requires authentication');
      return handleGraphQL(req, res, bodyBuf);
    }
    // MCP
    if (segments.length === 1 && segments[0] === 'mcp') {
      return handleMcp(req, res, bodyBuf);
    }
    return sendError(res, 404, 'Not Found');
  } catch (e) {
    console.error('[entry] request error:', e instanceof Error ? e.stack ?? e.message : String(e));
    if (!res.headersSent) sendError(res, 500, 'Internal Server Error');
    else res.end();
  }
}

// ---------------------------------------------------------------- lifecycle
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
async function pollDone(envUrl: string): Promise<void> {
  const base = envUrl.replace(/\/+$/, '');
  for (;;) {
    await sleep(500);
    try {
      const r = await fetch(`${base}/done`);
      const data = (await r.json()) as { done?: boolean };
      if (data.done === true) return;
    } catch {
      // Retry on transient errors; the env may not be up yet.
    }
  }
}
async function main(): Promise<void> {
  const listenPort = IS_LIFECYCLE ? 0 : Number(process.env.PORT ?? '0');
  const server = createServer((req, res) => {
    void handleRequest(req, res);
  });
  server.listen(listenPort, '127.0.0.1', () => {
    const address = server.address();
    const port = typeof address === 'object' && address !== null ? address.port : listenPort;
    console.log(`[entry] forge listening on 127.0.0.1:${port}`);
    if (!IS_LIFECYCLE) return;
    const base = ENV_URL.replace(/\/+$/, '');
    fetch(`${base}/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ port }),
    })
      .then(async (r) => {
        if (!r.ok) {
          console.error(`[entry] register failed: HTTP ${r.status}`);
          process.exit(1);
        }
        console.log('[entry] registered');
        await pollDone(ENV_URL);
        console.log('[entry] done, exiting');
        server.close();
        process.exit(0);
      })
      .catch((e) => {
        console.error('[entry] register error:', e instanceof Error ? e.message : String(e));
        process.exit(1);
      });
  });
}
process.on('uncaughtException', (e) => {
  console.error('[entry] uncaught:', e instanceof Error ? e.stack ?? e.message : String(e));
});
void main();
