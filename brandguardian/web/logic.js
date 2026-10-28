// Pure, DOM-free helpers. Everything here is unit-tested with `node --test tests/js`.

export const SEVERITY_RANK = { blocker: 0, warning: 1, info: 2 };
export const SEVERITY_LABEL = { blocker: 'Blocker', warning: 'Warning', info: 'Note' };

export const STATUS_LABELS = {
  draft: 'Draft',
  in_review: 'In review',
  changes_requested: 'Changes requested',
  approved: 'Approved',
  approved_with_conditions: 'Approved with conditions',
};

const ISSUE_LABELS = {
  wrong_term: 'Wrong term',
  restricted_phrase: 'Wording not permitted',
  unsupported_claim: 'Claim with no approved source',
  contradicted_fact: 'Contradicts an approved fact',
  expired_claim: 'Approval has expired',
  personal_data: 'Personal data',
  too_many_exclamations: 'Too many exclamation marks',
  repeated_exclamation: 'Repeated exclamation marks',
  all_caps: 'Word in capitals',
  long_sentences: 'Long sentences',
  missing_alt_text: 'Image without alt text',
  uninformative_alt_text: 'Alt text does not describe the image',
  vague_link_text: 'Vague link text',
  content_instruction: 'Instruction hidden in the copy',
  needs_human_review: 'Needs a person to decide',
};

export function issueLabel(type) {
  if (ISSUE_LABELS[type]) return ISSUE_LABELS[type];
  const words = String(type || 'Issue').replace(/_/g, ' ').trim();
  return words.charAt(0).toUpperCase() + words.slice(1);
}

export function worstSeverity(severities) {
  let best = null;
  for (const s of severities) {
    if (!(s in SEVERITY_RANK)) continue;
    if (best === null || SEVERITY_RANK[s] < SEVERITY_RANK[best]) best = s;
  }
  return best;
}

/** Split text into contiguous segments; each carries the ids and worst severity of the flags covering it. */
export function buildSegments(text, flags) {
  const valid = (flags || []).filter(
    (f) => Number.isInteger(f.start) && Number.isInteger(f.end) && f.start >= 0 && f.end > f.start && f.end <= text.length,
  );
  const cuts = new Set([0, text.length]);
  for (const f of valid) { cuts.add(f.start); cuts.add(f.end); }
  const points = [...cuts].sort((a, b) => a - b);
  const segments = [];
  for (let i = 0; i < points.length - 1; i += 1) {
    const start = points[i];
    const end = points[i + 1];
    if (end <= start) continue;
    const covering = valid.filter((f) => f.start <= start && f.end >= end);
    segments.push({
      start, end, text: text.slice(start, end),
      flagIds: covering.map((f) => f.id),
      severity: worstSeverity(covering.map((f) => f.severity)),
    });
  }
  return segments;
}

export function isApplicable(suggestion) {
  return (suggestion.action === 'replace' && typeof suggestion.text === 'string') || suggestion.action === 'delete';
}

function clip(text, n) {
  return text.length > n ? `${text.slice(0, n - 1)}…` : text;
}

export function suggestionLabel(s) {
  if (s.action === 'replace' && typeof s.text === 'string') return `Replace with “${clip(s.text, 36)}”`;
  if (s.action === 'delete') return 'Remove it';
  if (s.action === 'request_evidence') return 'Ask for evidence';
  return 'Edit by hand';
}

/** Mirror of the server's edit semantics, used only before a draft is saved. Returns null when not applicable. */
export function applyLocalEdit(text, flag, suggestion) {
  if (!isApplicable(suggestion)) return null;
  let start = suggestion.start == null ? flag.start : suggestion.start;
  let end = suggestion.end == null ? flag.end : suggestion.end;
  if (!(start >= 0 && start <= end && end <= text.length)) return null;
  const replacement = suggestion.action === 'delete' ? '' : suggestion.text;
  if (replacement === '') {
    if (start > 0 && end < text.length && text[start - 1] === ' ' && text[end] === ' ') end += 1;
    else if (start > 0 && text[start - 1] === ' ' && (end >= text.length || '.,!?;:'.includes(text[end]))) start -= 1;
  }
  return text.slice(0, start) + replacement + text.slice(end);
}

/** Parse newline-delimited JSON from a streamed buffer. Returns parsed events and the unfinished remainder. */
export function parseNdjson(buffer) {
  const lines = buffer.split('\n');
  const rest = lines.pop();
  const events = [];
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try { events.push(JSON.parse(trimmed)); } catch { /* ignore a malformed line rather than break the stream */ }
  }
  return { events, rest };
}

// Wrapped in arrow functions on purpose: browsers throw "Illegal invocation" if setTimeout is called with a foreign `this`.
const DEFAULT_TIMERS = { set: (fn, ms) => setTimeout(fn, ms), clear: (handle) => clearTimeout(handle) };

export function debounce(fn, ms, timers = DEFAULT_TIMERS) {
  let handle = null;
  const wrapped = (...args) => {
    if (handle !== null) timers.clear(handle);
    handle = timers.set(() => { handle = null; fn(...args); }, ms);
  };
  wrapped.cancel = () => { if (handle !== null) { timers.clear(handle); handle = null; } };
  return wrapped;
}

/** Turn server diff ops into display parts: {kind: same|removed|added, text}. */
export function diffParts(ops) {
  const parts = [];
  for (const op of ops) {
    if (op.op === 'equal') parts.push({ kind: 'same', text: op.old });
    else {
      if (op.old) parts.push({ kind: 'removed', text: op.old });
      if (op.new) parts.push({ kind: 'added', text: op.new });
    }
  }
  return parts;
}

const CAN = {
  write: ['creator', 'external', 'reviewer', 'manager'],
  insights: ['reviewer', 'manager', 'admin'],
  audit: ['reviewer', 'manager', 'admin'],
  review: ['reviewer', 'manager'],
};

/** UI gating only. The server enforces permissions; this just hides controls that would be refused. */
export function roleCan(role, action) {
  return (CAN[action] || []).includes(role);
}

export function countBlockers(flags) {
  return (flags || []).filter((f) => f.severity === 'blocker').length;
}

// The server reports offsets in Unicode code points; JavaScript strings index UTF-16 units. They differ for emoji and
// other astral characters, so offsets are converted on the way in and out to keep marks aligned with the text.
const SURROGATE = /[\ud800-\udfff]/;

export function cpToJs(text, cp) {
  let i = 0;
  let n = 0;
  while (n < cp && i < text.length) {
    i += text.codePointAt(i) > 0xffff ? 2 : 1;
    n += 1;
  }
  return i;
}

export function jsToCp(text, index) {
  return Array.from(text.slice(0, index)).length;
}

export function flagsToJs(text, flags) {
  if (!SURROGATE.test(text)) return flags;
  const conv = (v) => (v == null ? v : cpToJs(text, v));
  return flags.map((f) => ({
    ...f,
    start: conv(f.start),
    end: conv(f.end),
    suggestions: (f.suggestions || []).map((s) => ({ ...s, start: conv(s.start), end: conv(s.end) })),
  }));
}

export const GUIDE_STEPS = [
  'Sign in as Asha',
  'Load the sample post',
  'Fix the flags',
  'Submit for review',
  'Sign in as Meera and review',
  'Verify the receipt',
];

/** Which guided-path step the user is on, and what to do next. */
export function nextStep(ctx) {
  const { signedIn, role, hasText, saved, status, blockers, hasReceipt } = ctx;
  if (!signedIn) return { index: 0, hint: 'Choose Asha Rao (Creator) to start writing.' };
  if (hasReceipt) return { index: 5, hint: 'Open the receipt and press Verify. Then try changing the text in the database: verification fails.' };
  if (roleCan(role, 'review') && status === 'in_review') {
    return { index: 4, hint: 'Open the item, read the notes, then approve, approve with conditions, or request changes.' };
  }
  if (role === 'creator' || role === 'external') {
    if (status === 'in_review') return { index: 4, hint: 'Waiting for a reviewer. Sign in as Meera Iyer (Reviewer) to decide.' };
    if (!hasText) return { index: 1, hint: 'Press “Load sample post” to see Brand Guardian find problems as you watch.' };
    if (!saved) return { index: 2, hint: 'Accept or dismiss each note, then press Save draft so decisions are recorded.' };
    if (blockers > 0) return { index: 2, hint: `${blockers} blocking issue(s) remain. Accept a suggested fix on each one.` };
    return { index: 3, hint: 'No blockers left. Submit for review.' };
  }
  return { index: 4, hint: 'Open the Review queue to see what needs a decision.' };
}

export function formatBytes(n) {
  if (!Number.isFinite(n) || n < 0) return '0 bytes';
  if (n === 1) return '1 byte';
  if (n < 1024) return `${n} bytes`;
  return `${(n / 1024).toFixed(1)} KB`;
}

export function percent(value) {
  return value === null || value === undefined ? '—' : `${Math.round(value * 100)}%`;
}
