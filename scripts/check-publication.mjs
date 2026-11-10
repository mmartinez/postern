#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import { lstatSync, readFileSync, readlinkSync } from 'node:fs';

const oidPattern = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/;
const privatePath = /(?:^|[\s`"'(\/])(?:AGENTS\.md|CLAUDE\.md|(?:PLAN|TODO|MEMORY|PRD)(?:[-_.][\w.-]+)?\.md|docs\/proposals\.md|\.[\w-]+\/(?:agents|instructions|sessions|plans|memory)(?:\/|\b)|\.[\w-]+\/settings(?:\.local)?\.json)(?=$|[\s`"')/])/;
const standards = /\b(?:SHA-(?:1|224|256|384|512)|UTF-(?:8|16|32)|RFC-\d{1,5}|BSD-[234]-Clause|(?:A?GPL|LGPL)-(?:2\.0|2\.1|3\.0)(?:-only|-or-later)?|CC0-[1]\.0|TEST-NET-[123]|LICENSE-[2]\.0)\b/gi;
const tracker = /(?<![\w-])[A-Z][A-Z0-9]{1,11}-\d+(?![\w-]|\.\d)/;
const provenance = [
  /^\s*(?:[>*#-]\s*)?(?:\u{1f916}\s*)?(?:generated|authored|implemented|written)\s+(?:with|by)\s+/iu,
  /\bco-authored-by\s*:.*(?:\bbot\b|\bassistant\b|\bagent\b|\bAI\b|\bmodel\b)/i,
  /\b(?:agent|session|run|harness|model)[ _-](?:id|name|version)\s*[:=]\s*[\w"']/i,
  /\b(?:agent|history|session|artifact|proc):\/\//i,
  /\b(?:executed|implemented|authored|generated)\s+(?:with|by|using)\s+(?:an?\s+)?(?:agent|model|assistant|harness)\b/i,
  /\bfresh[ -]context (?:reviewer|agent)\b/i,
  /\b(?:review|audit|analysis)\s*\([^)]*[\w.-]+\/[\w.-]+\s+via\s+[\w.-]+/i,
];
let findings = 0;
const seenBlobs = new Set();

function invalid() {
  throw new Error('invalid input');
}

function run(command, args) {
  return execFileSync(command, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 64 * 1024 * 1024 });
}

function git(...args) {
  return run('git', args);
}

function report(path, category, line = 1) {
  console.error(`publication: ${JSON.stringify(path)}:${line}: ${category}`);
  findings++;
}

function text(value, label, metadata = false, ignorePaths = false) {
  if (typeof value !== 'string') invalid();
  for (const [index, line] of value.split('\n').entries()) {
    const normalized = line.replace(standards, '');
    if (tracker.test(normalized)) report(label, 'tracker', index + 1);
    if (!ignorePaths && privatePath.test(line)) report(label, 'private-path', index + 1);
    if (provenance.some((pattern) => pattern.test(line)) ||
        (metadata && (/^\s*(?:[-*]\s*)?(?:model|harness|agent)\s*:\s*\S/i.test(line) ||
          /^(?:author|committer|tagger)[ :].*(?:\bagent\b|\bassistant\b|\bmodel\b)/i.test(line)))) {
      report(label, 'provenance', index + 1);
    }
    for (const match of line.matchAll(/https?:\/\/[^\s<>"'`)]+/gi)) {
      const decoded = match[0].replace(/%([a-f0-9]{2})/gi, (_, hex) => String.fromCharCode(Number.parseInt(hex, 16)));
      const [authority, ...parts] = decoded.replace(/^https?:\/\//i, '').split('/');
      const hostname = authority.slice(authority.lastIndexOf('@') + 1).split(':')[0].toLowerCase();
      const pathname = `/${parts.join('/')}`;
      if (!['github.com', 'gitlab.com'].includes(hostname) &&
          (/(?:^|\.)(?:internal|private|tracker|tickets|workspace|intranet)(?:\.|$)/i.test(hostname) ||
           /\/(?:issues?|tasks?|tickets?|browse|workspaces?|teams?|projects?)\//i.test(pathname))) {
        report(label, 'private-link', index + 1);
      }
      if (tracker.test(pathname.replace(standards, ''))) {
        report(label, 'tracker', index + 1);
      }
    }
  }
}

function branch(value, label = 'branch') {
  if (typeof value !== 'string' || !value) invalid();
  git('check-ref-format', '--branch', value);
  text(value.toUpperCase(), label);
  if (/^(?:agents?|assistants?|sessions?|runs?|harness|models?|bots?)[\/_-]/i.test(value)) report(label, 'branch');
}

function currentBranch() {
  branch(git('symbolic-ref', '--quiet', '--short', 'HEAD').trim());
}

function file(path, value) {
  const before = findings;
  text(path, 'file path');
  if (findings !== before) return;
  text(value, path, false, ['.gitignore', '.dockerignore'].includes(path));
}

function entries(output) {
  return output.split('\0').filter(Boolean).map((entry) => {
    const tab = entry.indexOf('\t');
    if (tab < 0) invalid();
    return [entry.slice(0, tab).split(' '), entry.slice(tab + 1)];
  });
}

function blob(path, oid) {
  const key = `${path}\0${oid}`;
  if (seenBlobs.has(key)) return;
  seenBlobs.add(key);
  file(path, git('cat-file', 'blob', oid));
}

function staged() {
  currentBranch();
  for (const [[mode, oid, stage], path] of entries(git('ls-files', '--stage', '-z'))) {
    if (stage !== '0' || mode === '160000') invalid();
    blob(path, oid);
  }
}

function workingTree() {
  currentBranch();
  for (const path of git('ls-files', '-z').split('\0').filter(Boolean)) {
    const stat = lstatSync(path);
    if (!stat.isFile() && !stat.isSymbolicLink()) invalid();
    file(path, stat.isSymbolicLink() ? readlinkSync(path) : readFileSync(path, 'utf8'));
  }
}

function commit(value) {
  if (typeof value !== 'string' || !value || value.startsWith('-')) invalid();
  const oid = git('rev-parse', '--verify', '--end-of-options', `${value}^{commit}`).trim();
  if (!oidPattern.test(oid)) invalid();
  return oid;
}

function tree(oid) {
  for (const [[mode, type, object], path] of entries(git('ls-tree', '-r', '-z', oid))) {
    if (type !== 'blob' || mode === '160000') invalid();
    blob(path, object);
  }
}

function commits(base, head) {
  return git('rev-list', '--reverse', `${commit(base)}..${commit(head)}`).trim().split('\n').filter(Boolean);
}

function range(base, head) {
  const tip = commit(head);
  for (const oid of commits(base, tip)) {
    text(git('show', '-s', '--format=%B%nAuthor: %an <%ae>%nCommitter: %cn <%ce>', oid), 'commit', true);
    tree(oid);
  }
  tree(tip);
}

function hash(value) {
  if (typeof value !== 'string' || !oidPattern.test(value) || /^0+$/.test(value)) invalid();
  return value;
}

function event(path) {
  const data = JSON.parse(readFileSync(path, 'utf8'));
  switch (process.env.GITHUB_EVENT_NAME) {
    case 'pull_request': {
      const pr = data.pull_request;
      if (!pr || !pr.title || (pr.body !== null && typeof pr.body !== 'string')) invalid();
      text(pr.title, 'pull request title', true);
      text(pr.body ?? '', 'pull request body', true);
      branch(pr.head?.ref, 'pull request branch');
      range(hash(pr.base?.sha), hash(pr.head?.sha));
      break;
    }
    case 'push':
      if (typeof data.ref !== 'string' || !data.ref.startsWith('refs/heads/')) invalid();
      branch(data.ref.slice('refs/heads/'.length), 'push branch');
      range(hash(data.before), hash(data.after));
      break;
    case 'workflow_dispatch':
      branch(data.ref, 'dispatch branch');
      tree(commit('HEAD'));
      break;
    default:
      invalid();
  }
}

function prePush(remote) {
  if (!/^[\w.-]+$/.test(remote)) invalid();
  const input = readFileSync(0, 'utf8').trim();
  if (!input) invalid();
  for (const line of input.split('\n')) {
    const fields = line.trim().split(/\s+/);
    if (fields.length !== 4) invalid();
    const [localRef, localOid, remoteRef, remoteOid] = fields;
    if (!oidPattern.test(localOid) || !oidPattern.test(remoteOid)) invalid();
    git('check-ref-format', remoteRef);
    if (/^0+$/.test(localOid)) {
      if (localRef !== '(delete)' || /^0+$/.test(remoteOid)) invalid();
      continue;
    }
    if (!/^refs\/(heads|tags)\//.test(remoteRef)) invalid();
    if (localRef.startsWith('refs/heads/')) branch(localRef.slice('refs/heads/'.length), 'local branch');
    branch(remoteRef.replace(/^refs\/(?:heads|tags)\//, ''), 'outgoing ref');
    if (git('cat-file', '-t', localOid).trim() === 'tag') {
      text(git('cat-file', 'tag', localOid), 'tag', true);
    }
    const base = /^0+$/.test(remoteOid) ? `refs/remotes/${remote}/main` : remoteOid;
    range(base, localOid);
  }
}

function api(path) {
  return JSON.parse(run('gh', ['api', '--paginate', '--slurp', path]));
}

function releaseInputs() {
  const repository = process.env.GITHUB_REPOSITORY;
  if (!/^[\w.-]+\/[\w.-]+$/.test(repository ?? '') || !process.env.GH_TOKEN) invalid();
  const releases = api(`repos/${repository}/releases/latest`);
  const tag = releases[0]?.tag_name;
  if (!/^v\d+\.\d+\.\d+(?:-[\w.]+)?$/.test(tag ?? '')) invalid();
  const base = commit(`refs/tags/${tag}`);
  const head = commit('HEAD');
  git('merge-base', '--is-ancestor', base, head);
  tree(head);
  for (const oid of commits(base, head)) {
    const pages = api(`repos/${repository}/commits/${oid}/pulls?per_page=100`);
    if (!Array.isArray(pages) || pages.some((page) => !Array.isArray(page))) invalid();
    const prs = pages.flat().filter((pr) => pr.merged_at && pr.merge_commit_sha === oid);
    if (prs.length > 1) invalid();
    let message = git('show', '-s', '--format=%B', oid);
    if (prs.length === 1) {
      const pr = prs[0];
      if (typeof pr.title !== 'string' || (pr.body !== null && typeof pr.body !== 'string')) invalid();
      text(pr.title, 'merged pull request title', true);
      text(pr.body ?? '', 'merged pull request body', true);
      const body = pr.body ?? '';
      const start = 'BEGIN_COMMIT_OVERRIDE';
      const end = 'END_COMMIT_OVERRIDE';
      if (body.includes(start) || body.includes(end)) {
        const match = body.match(/^BEGIN_COMMIT_OVERRIDE\r?\n([\s\S]+?)\r?\nEND_COMMIT_OVERRIDE\s*$/m);
        if (!match || body.split(start).length !== 2 || body.split(end).length !== 2 ||
            git('show', '-s', '--format=%P', oid).trim().split(' ').length !== 1) invalid();
        message = match[1];
        if (!message.trim()) invalid();
      }
    }
    text(message, 'release commit', true);
  }
}

try {
  const args = process.argv.slice(2);
  if (args.length === 0) workingTree();
  else if (args.length === 1 && args[0] === '--staged') staged();
  else if (args.length === 1 && args[0] === '--release-inputs') releaseInputs();
  else if (args.length === 2 && args[1]) {
    switch (args[0]) {
      case '--message-file': {
        const message = readFileSync(args[1], 'utf8');
        if (!message.trim()) invalid();
        text(message, 'message', true);
        break;
      }
      case '--range': {
        const match = args[1].match(/^([^\s]+)\.\.([^\s]+)$/);
        if (!match || match[1].includes('..') || match[2].includes('..') || match[2].startsWith('.')) invalid();
        range(match[1], match[2]);
        break;
      }
      case '--event': event(args[1]); break;
      case '--pre-push': prePush(args[1]); break;
      default: invalid();
    }
  } else invalid();
  process.exitCode = findings ? 1 : 0;
} catch {
  console.error('publication: input unavailable or invalid');
  process.exitCode = 1;
}
