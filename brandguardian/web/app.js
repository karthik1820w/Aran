import {
  buildSegments, applyLocalEdit, issueLabel, suggestionLabel, isApplicable, parseNdjson, debounce, diffParts,
  STATUS_LABELS, SEVERITY_LABEL, GUIDE_STEPS, nextStep, roleCan, countBlockers, flagsToJs, jsToCp, formatBytes, percent,
} from './logic.js';

/* ---------------------------------------------------------------- small DOM helpers (no innerHTML anywhere) */
const $ = (id) => document.getElementById(id);
const clear = (el) => { while (el.firstChild) el.removeChild(el.firstChild); return el; };
// DOM append() turns null into the text "null"; this skips empty values instead.
const add = (parent, ...kids) => { for (const k of kids.flat()) if (k !== null && k !== undefined && k !== false) parent.append(k); return parent; };

function h(tag, attrs = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === false || v === null || v === undefined) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? '' : String(v));
  }
  for (const kid of kids.flat()) {
    if (kid === null || kid === undefined || kid === false) continue;
    el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

let toastTimer = null;
function toast(message, kind = 'info') {
  const el = $('toast');
  el.textContent = message;
  el.className = `toast show ${kind === 'error' ? 'error' : ''}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.className = 'toast'; }, 4200);
}

const ROLE_BLURB = {
  creator: 'Writes content and submits it for review',
  external: 'Agency view: sees only their own work',
  reviewer: 'Approves, or requests changes',
  manager: 'Owns the guidelines, sees insights',
  admin: 'Sees audit and insights; cannot write or approve',
};

/* ---------------------------------------------------------------- state */
const state = {
  token: sessionStorage.getItem('bg_token'),
  user: null, status: null, kb: null, tab: 'write',
  contentId: null, content: null, savedText: '', text: '',
  flags: [], claims: [], checks: [], profile: null, ai: null,
  stale: false, dismissed: new Map(), simulate: false, controller: null,
  detail: null, receipt: null, openedReceipt: false,
};

/* ---------------------------------------------------------------- API */
async function api(method, path, body) {
  const headers = {};
  if (state.token) headers.Authorization = `Bearer ${state.token}`;
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const res = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  let data = null;
  try { data = await res.json(); } catch { /* empty body */ }
  if (!res.ok) {
    if (res.status === 401 && state.token && !path.startsWith('/api/demo')) {
      toast('Your session ended. Please sign in again.', 'error');
      await signOut(true);
    }
    const err = new Error((data && data.error && data.error.message) || `Request failed (${res.status})`);
    err.status = res.status;
    err.code = data && data.error && data.error.code;
    err.data = data;
    throw err;
  }
  return data;
}

/* ---------------------------------------------------------------- navigation and chrome */
const VIEWS = ['login', 'write', 'queue', 'insights', 'trust', 'about'];

function showView(name) {
  for (const v of VIEWS) $(`view-${v}`).hidden = v !== name;
  for (const b of document.querySelectorAll('#tabs button')) {
    if (b.dataset.tab === name) b.setAttribute('aria-current', 'page'); else b.removeAttribute('aria-current');
  }
}

function renderChrome() {
  const signedIn = Boolean(state.user);
  $('chips').hidden = !signedIn;
  $('tabs').hidden = !signedIn;
  $('guide').hidden = !signedIn && !state.status;
  $('guideHint').hidden = $('guide').hidden;
  if (!signedIn) return;
  $('who').textContent = state.user.name;
  const ai = state.status && state.status.ai;
  $('chipAi').textContent = ai && ai.enabled ? `AI judge: ${ai.provider}` : 'AI judge: off, exact checks only';
  $('chipAi').className = `chip ${ai && ai.enabled ? 'on' : ''}`;
  const role = state.user.role;
  for (const b of document.querySelectorAll('#tabs button')) {
    const t = b.dataset.tab;
    b.hidden = (t === 'write' && !roleCan(role, 'write')) || (t === 'insights' && !roleCan(role, 'insights'));
  }
  $('trapRow').hidden = !(state.status && state.status.demo_mode);
}

async function refreshOutChip() {
  try {
    const flow = await api('GET', '/api/dataflow');
    $('chipOut').textContent = `Sent outside: ${formatBytes(flow.external_bytes_sent)}`;
    $('chipOut').className = `chip ${flow.external_bytes_sent === 0 ? 'on' : ''}`;
  } catch { /* chip is informational */ }
}

function renderGuide() {
  const ctx = {
    signedIn: Boolean(state.user), role: state.user && state.user.role,
    hasText: state.text.trim().length > 0, saved: Boolean(state.contentId) && state.text === state.savedText,
    status: state.content && state.content.status,
    blockers: countBlockers(state.flags),
    hasReceipt: Boolean(state.content && state.content.receipts && state.content.receipts.length) || state.openedReceipt,
  };
  const step = nextStep(ctx);
  const list = clear($('guide'));
  GUIDE_STEPS.forEach((label, i) => {
    list.append(h('li', { class: i < step.index ? 'done' : i === step.index ? 'current' : '', 'aria-current': i === step.index ? 'step' : false }, label));
  });
  $('guideHint').textContent = step.hint;
  $('guide').hidden = false;
  $('guideHint').hidden = false;
}

async function setTab(name) {
  state.tab = name;
  showView(name);
  renderGuide();
  if (name === 'write') renderWrite();
  if (name === 'queue') await loadQueue();
  if (name === 'insights') await loadInsights();
  if (name === 'trust') await loadTrust();
  if (name === 'about') renderAbout();
  $('main').focus({ preventScroll: true });
}

/* ---------------------------------------------------------------- sign in and out */
// Remove everything the previous user could see, so the next person on a shared computer never sees it.
function wipeViews() {
  for (const id of ['queueList', 'detail', 'insightsBody', 'xray', 'auditBody', 'aboutBody', 'receiptBox', 'notesList', 'claims', 'checks']) {
    if ($(id)) clear($(id));
  }
  state.detail = null; state.status = state.status && { ...state.status };
  $('chipOut').textContent = '';
}

async function showLogin(message) {
  state.user = null; state.token = null;
  sessionStorage.removeItem('bg_token');
  resetEditor();
  wipeViews();
  renderChrome();
  showView('login');
  $('guide').hidden = false;
  renderGuide();
  const box = clear($('accounts'));
  try {
    const { users } = await api('GET', '/api/demo/users');
    for (const u of users) {
      box.append(h('button', { type: 'button', class: 'account', role: 'listitem', onclick: () => login(u.id) },
        h('strong', {}, u.name), h('span', {}, ROLE_BLURB[u.role] || u.role), h('em', {}, 'Sign in')));
    }
  } catch {
    box.append(h('p', { class: 'small' }, 'Demo accounts are switched off on this server. Paste an access token from your administrator.'));
    const input = h('input', { type: 'password', id: 'tokenInput', 'aria-label': 'Access token', autocomplete: 'off' });
    box.append(h('div', { class: 'panel' }, input,
      h('button', { type: 'button', class: 'btn primary', onclick: async () => {
        state.token = input.value.trim();
        try { await enterApp(); sessionStorage.setItem('bg_token', state.token); } catch { state.token = null; toast('That token was not accepted.', 'error'); }
      } }, 'Sign in')));
  }
  if (message) toast(message);
}

async function login(userId) {
  try {
    const out = await api('POST', '/api/demo/login', { user_id: userId });
    state.token = out.token;
    sessionStorage.setItem('bg_token', out.token);
    resetEditor();
    await enterApp();
  } catch (e) { toast(e.message, 'error'); }
}

async function signOut(silent) {
  if (state.controller) state.controller.abort();
  await showLogin(silent ? undefined : 'Signed out.');
}

async function enterApp() {
  const me = await api('GET', '/api/me');
  state.user = me.user;
  const [kb, status] = await Promise.all([api('GET', '/api/kb'), api('GET', '/api/status')]);
  state.kb = kb; state.status = status;
  renderChrome();
  await setTab(roleCan(state.user.role, 'write') ? 'write' : 'queue');
  refreshOutChip();
}

/* ---------------------------------------------------------------- editor state */
function resetEditor() {
  if (state.controller) state.controller.abort();
  Object.assign(state, {
    contentId: null, content: null, savedText: '', text: '', flags: [], claims: [], checks: [], profile: null, ai: null,
    stale: false, dismissed: new Map(), controller: null, openedReceipt: false,
  });
  if ($('text')) { $('text').value = ''; $('title').value = ''; }
}

const isDirty = () => state.text !== state.savedText;
const status = () => (state.content ? state.content.status : 'draft');
const locked = () => status() === 'in_review';
const canServerAct = () => Boolean(state.contentId) && !isDirty() && !state.stale && !locked();

function setText(text, { keepFlags = false } = {}) {
  state.text = text;
  $('text').value = text;
  if (!keepFlags) state.stale = true;
  renderEditor();
  scheduleReview();
}

function applyContent(content) {
  state.content = content;
  state.contentId = content.id;
  state.savedText = content.latest.text;
  state.text = content.latest.text;
  $('text').value = state.text;
  $('title').value = content.title;
  state.dismissed = new Map();
  const review = content.latest.review;
  if (review) {
    state.flags = flagsToJs(state.text, review.flags);
    state.claims = review.claims; state.checks = review.checks.map((c) => ({ ...c, state: 'ran' }));
    state.profile = review.profile; state.ai = review.ai; state.stale = false;
    for (const d of content.decisions || []) {
      if (d.version_n === content.latest.n && d.action === 'dismissed') state.dismissed.set(d.flag_id, d.reason);
    }
  } else {
    state.stale = true;
  }
  renderWrite();
  if (!review) scheduleReview();
}

/* ---------------------------------------------------------------- live review (streamed) */
async function liveReview() {
  if (state.controller) state.controller.abort();
  const text = state.text;
  if (!text.trim()) {
    Object.assign(state, { flags: [], claims: [], checks: [], profile: null, ai: null, stale: false });
    renderEditor();
    return;
  }
  const controller = new AbortController();
  state.controller = controller;
  state.checks = [];
  const flags = []; const claims = [];
  try {
    const res = await fetch('/api/review/stream', {
      method: 'POST', signal: controller.signal,
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${state.token}` },
      body: JSON.stringify({ text, simulate: state.simulate }),
    });
    if (!res.ok) {
      let message = `Review failed (${res.status})`;
      try { message = (await res.json()).error.message; } catch { /* keep default */ }
      throw new Error(message);
    }
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const parsed = parseNdjson(buffer);
      buffer = parsed.rest;
      for (const ev of parsed.events) {
        if (controller.signal.aborted || state.text !== text) return;
        if (ev.type === 'detector') {
          flags.push(...ev.flags); claims.push(...ev.claims);
          state.checks.push({ id: ev.id, name: ev.name, ms: ev.ms, state: 'ran' });
          state.flags = flagsToJs(text, [...flags].sort((a, b) => a.start - b.start));
          state.claims = claims; state.stale = false;
        } else if (ev.type === 'ai') {
          state.ai = ev.ai;
        } else if (ev.type === 'done') {
          state.flags = flagsToJs(text, ev.result.flags);
          state.claims = ev.result.claims; state.profile = ev.result.profile; state.ai = ev.result.ai;
          state.checks = ev.result.checks.map((c) => ({ ...c, state: 'ran' }));
          state.stale = false;
        } else if (ev.type === 'error') {
          throw new Error(ev.message);
        }
        renderEditor();
      }
    }
  } catch (e) {
    if (e.name === 'AbortError') return;
    toast(e.message, 'error');
  } finally {
    if (state.controller === controller) state.controller = null;
    renderGuide();
    refreshOutChip();
  }
}
const scheduleReview = debounce(liveReview, 450);

/* ---------------------------------------------------------------- rendering: editor */
function visibleFlags() { return state.flags.filter((f) => !state.dismissed.has(f.id)); }

function renderMarks() {
  const backdrop = clear($('backdrop'));
  const segs = buildSegments(state.text, state.stale ? [] : visibleFlags());
  for (const s of segs) {
    if (s.severity) backdrop.append(h('span', { class: `mark sev-${s.severity}`, 'data-flags': s.flagIds.join(' ') }, s.text));
    else backdrop.append(document.createTextNode(s.text));
  }
  backdrop.append(document.createTextNode('\u200b'));
  backdrop.scrollTop = $('text').scrollTop;
}

function renderStatusBits() {
  const st = status();
  const badge = $('statusBadge');
  badge.textContent = state.contentId ? STATUS_LABELS[st] : 'Unsaved';
  badge.className = `badge ${state.contentId ? st : ''}`;
  const banner = $('lockBanner');
  banner.hidden = !(locked() || st === 'approved' || st === 'approved_with_conditions' || st === 'changes_requested');
  if (locked()) banner.textContent = 'In review. The text is locked until a reviewer decides. A reviewer can request changes to unlock it.';
  else if (st === 'changes_requested') banner.textContent = 'A reviewer asked for changes. Edit the text, then submit again.';
  else if (!banner.hidden) banner.textContent = 'Approved. A receipt records exactly what was approved. Editing starts a new version that needs approval again.';
  $('text').readOnly = locked();
  $('title').readOnly = Boolean(state.contentId);
  $('save').disabled = locked() || !state.text.trim() || (Boolean(state.contentId) && !isDirty());
  $('submit').disabled = locked() || !state.text.trim() || !['draft', 'changes_requested', 'unsaved'].includes(state.contentId ? st : 'unsaved')
    || ['approved', 'approved_with_conditions'].includes(st);
  $('dirty').textContent = state.contentId ? (isDirty() ? 'Unsaved changes' : `Saved as version ${state.content ? state.content.latest.n : 1}`) : (state.text ? 'Not saved yet' : '');
}

function renderVoice() {
  const p = state.profile;
  $('voice').textContent = p ? `Voice: ${p.avg_sentence_words} words per sentence · ${p.exclamation_marks} exclamation mark(s) · ${p.caps_words} capitalised word(s) · ${p.words} words` : '';
}

function renderChecks() {
  const box = clear($('checks'));
  if (!state.text.trim()) return;
  if (!state.checks.length) { box.append(h('span', { class: 'check busy' }, 'Checking…')); return; }
  for (const c of state.checks) box.append(h('span', { class: 'check ran', title: `${c.name}${c.ms !== undefined ? `, ${c.ms} ms` : ''}` }, c.name));
}

function renderAiLine() {
  const line = clear($('aiLine'));
  const ai = state.ai;
  if (!ai || !state.text.trim()) return;
  if (ai.status === 'off') { line.append('AI judge is off, so only exact checks ran. Every flag below is a rule match with a quoted source.'); return; }
  if (ai.status === 'error') { line.append(`AI judge unavailable: ${ai.message}`); return; }
  const v = ai.verifier;
  const simulated = ai.provider === 'simulated-unreliable-model';
  line.append(h('strong', {}, simulated ? 'Simulated unreliable model. ' : `AI judge (${ai.provider}). `),
    `Verifier accepted ${v.accepted}, `, h('span', { class: 'rej' }, `rejected ${v.rejected}`),
    v.rejected ? ` (${Object.entries(v.reasons).map(([k, n]) => `${k.replace(/_/g, ' ')} ×${n}`).join(', ')})` : '', '.');
  if (ai.external) line.append(' Text was redacted before it was sent.');
}

function renderClaims() {
  const box = clear($('claims'));
  box.hidden = !state.claims.length;
  if (!state.claims.length) return;
  box.append(h('h3', {}, 'Claims found and what the Claim Ledger says'));
  for (const c of state.claims) box.append(h('span', { class: `claim ${c.verdict}`, title: c.detail }, h('b', {}, c.verdict), `“${c.text}”`));
}

function renderNotes() {
  const list = clear($('notesList'));
  const flags = visibleFlags();
  const dismissed = state.flags.filter((f) => state.dismissed.has(f.id));
  $('noteCount').textContent = flags.length ? String(flags.length) : '';
  const hint = $('notesHint');
  if (!state.text.trim()) hint.textContent = 'Notes appear here as you write. Each one names the rule or approved fact it relies on.';
  else if (!flags.length && !state.stale && state.checks.length) hint.textContent = 'No open notes. Nothing in this draft breaks a rule or contradicts an approved fact.';
  else if (state.stale) hint.textContent = 'Updating…';
  else hint.textContent = '';
  list.classList.toggle('stale', state.stale);
  for (const f of flags) list.append(h('li', {}, noteCard(f)));
  if (dismissed.length) {
    const body = h('ol', { class: 'note-list' });
    for (const f of dismissed) {
      body.append(h('li', {}, h('div', { class: 'note sev-info' },
        h('div', { class: 'note-top' }, h('span', { class: 'note-title' }, issueLabel(f.issue_type)), h('span', { class: 'note-text' }, `“${f.text}”`)),
        h('p', { class: 'small' }, `Dismissed: ${state.dismissed.get(f.id)}`),
        f.severity === 'blocker' ? h('p', { class: 'still' }, 'Still blocks approval until fixed or overridden by a reviewer.') : null)));
    }
    list.append(h('li', {}, h('details', {}, h('summary', {}, `Dismissed (${dismissed.length})`), body)));
  }
}

function noteCard(flag, { readOnly = false } = {}) {
  const sev = flag.severity;
  const actions = h('div', { class: 'note-actions' });
  const extras = [];
  if (!readOnly) {
    flag.suggestions.forEach((s, i) => {
      if (isApplicable(s)) {
        actions.append(h('button', { type: 'button', class: `btn ${i === 0 ? 'primary' : ''}`, title: s.note || '', onclick: () => accept(flag, i) }, suggestionLabel(s)));
      } else {
        extras.push(h('p', { class: 'small' }, `${suggestionLabel(s)}: ${s.note}`));
      }
    });
  }
  const reasonRow = h('div', { class: 'dismiss-row', hidden: true });
  if (!readOnly) {
    const input = h('input', { type: 'text', 'aria-label': 'Reason for dismissing', placeholder: 'Why is this fine? (min. 5 characters)', maxlength: 300 });
    reasonRow.append(input, h('button', { type: 'button', class: 'btn', onclick: () => dismiss(flag, input.value) }, 'Dismiss'));
    actions.append(h('button', { type: 'button', class: 'btn hand', onclick: () => { reasonRow.hidden = !reasonRow.hidden; if (!reasonRow.hidden) input.focus(); } }, 'Dismiss…'));
  }
  const card = h('div', { class: `note sev-${sev}`, 'data-flag': flag.id, tabindex: 0 },
    h('div', { class: 'note-top' },
      h('span', { class: `pill sev-${sev}` }, SEVERITY_LABEL[sev]),
      flag.method === 'ai' ? h('span', { class: 'pill ai' }, 'AI') : null,
      flag.verdict ? h('span', { class: `pill v-${flag.verdict}` }, flag.verdict) : null,
      h('span', { class: 'note-title' }, issueLabel(flag.issue_type))),
    h('div', {}, h('span', { class: 'note-text' }, `“${flag.text.length > 90 ? `${flag.text.slice(0, 89)}…` : flag.text}”`)),
    h('p', {}, flag.explanation),
    h('div', { class: 'seal' },
      h('span', { class: 'seal-label' }, `✓ Verified source · ${flag.rule_id}`),
      h('blockquote', {}, flag.evidence_quote),
      h('cite', {}, `${flag.source}${flag.method === 'ai' ? ` · model confidence ${flag.confidence}` : ''}`)),
    actions, reasonRow, extras);
  if (!readOnly) {
    const focusMark = () => {
      const ta = $('text');
      ta.focus({ preventScroll: true });
      ta.setSelectionRange(flag.start, flag.end);
    };
    card.addEventListener('click', (ev) => { if (!ev.target.closest('button, input')) focusMark(); });
    card.addEventListener('mouseenter', () => highlight(flag.id, true));
    card.addEventListener('mouseleave', () => highlight(flag.id, false));
  }
  return card;
}

function highlight(flagId, on) {
  for (const m of document.querySelectorAll('#backdrop .mark')) {
    if ((m.dataset.flags || '').split(' ').includes(flagId)) m.classList.toggle('active', on);
  }
}

function renderEditor() {
  renderMarks(); renderStatusBits(); renderVoice(); renderChecks(); renderAiLine(); renderClaims(); renderNotes(); renderGuide();
}

function renderWrite() {
  renderEditor();
  renderReceiptBox();
}

/* ---------------------------------------------------------------- editor actions */
async function accept(flag, index) {
  if (canServerAct()) {
    try {
      const out = await api('POST', `/api/content/${state.contentId}/flags/${flag.id}/accept`, { suggestion_index: index });
      applyContent(out.content);
      toast(`Fix applied. Saved as version ${out.version}.`);
    } catch (e) { toast(e.message, 'error'); }
    return;
  }
  const next = applyLocalEdit(state.text, flag, flag.suggestions[index]);
  if (next === null) { toast('That one needs a person to edit the text.'); return; }
  setText(next);
  toast(state.contentId ? 'Applied to the editor. Save to record it as a new version.' : 'Applied to the editor.');
}

async function dismiss(flag, reason) {
  if (reason.trim().length < 5) { toast('Please give a reason (at least 5 characters).', 'error'); return; }
  if (canServerAct()) {
    try {
      await api('POST', `/api/content/${state.contentId}/flags/${flag.id}/dismiss`, { reason });
      state.dismissed.set(flag.id, reason.trim());
      renderEditor();
      toast(flag.severity === 'blocker' ? 'Dismissal recorded. It still blocks approval.' : 'Dismissal recorded.');
    } catch (e) { toast(e.message, 'error'); }
    return;
  }
  state.dismissed.set(flag.id, reason.trim());
  renderEditor();
}

async function save() {
  const title = $('title').value.trim() || 'Untitled draft';
  if (!state.text.trim()) { toast('Write something first.', 'error'); return null; }
  try {
    if (!state.contentId) {
      const created = await api('POST', '/api/content', { title, text: state.text });
      state.contentId = created.id;
    } else if (isDirty()) {
      await api('POST', `/api/content/${state.contentId}/versions`, { text: state.text });
    }
    await api('POST', `/api/content/${state.contentId}/check`, { simulate: state.simulate });
    applyContent(await api('GET', `/api/content/${state.contentId}`));
    refreshOutChip();
    return state.content;
  } catch (e) { toast(e.message, 'error'); return null; }
}

async function submitForReview() {
  if (!state.contentId || isDirty()) { if (!(await save())) return; }
  try {
    applyContent(await api('POST', `/api/content/${state.contentId}/submit`, {}));
    toast('Submitted. A reviewer will decide.');
  } catch (e) { toast(e.message, 'error'); }
}

async function loadSample() {
  resetEditor();
  $('title').value = 'Launch post (sample)';
  state.text = state.kb.sample_post;
  $('text').value = state.text;
  state.stale = true;
  renderEditor();
  await save();
}

/* ---------------------------------------------------------------- receipts */
async function receiptCard(receiptId) {
  const rec = await api('GET', `/api/receipts/${receiptId}`);
  const b = rec.body;
  const out = h('div', { class: 'verify', 'aria-live': 'polite' });
  const card = h('div', { class: 'receipt' },
    h('h3', {}, `Approval receipt · ${STATUS_LABELS[b.decision] || b.decision}`),
    h('dl', {},
      h('dt', {}, 'Approved by'), h('dd', {}, `${b.approver.name}`),
      h('dt', {}, 'Version'), h('dd', {}, String(b.version)),
      h('dt', {}, 'Content hash'), h('dd', {}, b.content_hash),
      h('dt', {}, 'Guidelines'), h('dd', {}, b.knowledge_base.version),
      h('dt', {}, 'Checks run'), h('dd', {}, b.checks_run.join(', ') || 'none recorded'),
      h('dt', {}, 'Overrides'), h('dd', {}, b.overrides.length ? b.overrides.map((o) => `${o.rule_id}: ${o.reason}`).join(' | ') : 'none'),
      h('dt', {}, 'Signature'), h('dd', {}, `${b.algorithm} ${rec.signature.slice(0, 24)}…`)),
    h('div', {}, h('button', { type: 'button', class: 'btn ok', onclick: async () => {
      state.openedReceipt = true; renderGuide();
      try {
        const v = await api('GET', `/api/receipts/${receiptId}/verify`);
        clear(out);
        const labels = {
          signature_valid: 'Signature matches the receipt', content_unchanged: 'Approved text is unchanged',
          audit_chain_intact: 'Audit chain is intact', audit_entry_matches: 'Audit entry matches the receipt',
        };
        for (const [k, ok] of Object.entries(v.checks)) out.append(h('div', { class: ok ? 'pass' : 'fail' }, `${labels[k]}${ok ? '' : ': FAILED'}`));
        out.append(h('strong', {}, v.valid ? 'Receipt verified.' : 'Receipt could NOT be verified.'));
      } catch (e) { toast(e.message, 'error'); }
    } }, 'Verify receipt')),
    out);
  return card;
}

async function renderReceiptBox() {
  const box = clear($('receiptBox'));
  const receipts = (state.content && state.content.receipts) || [];
  if (!receipts.length || isDirty()) return;
  try { box.append(await receiptCard(receipts[receipts.length - 1].id)); } catch { /* receipt is optional UI */ }
}

/* ---------------------------------------------------------------- review queue */
async function loadQueue() {
  const { items } = await api('GET', '/api/content');
  const order = { in_review: 0, changes_requested: 1, draft: 2, approved_with_conditions: 3, approved: 3 };
  items.sort((a, b) => (order[a.status] - order[b.status]) || b.updated_at.localeCompare(a.updated_at));
  const list = clear($('queueList'));
  if (!items.length) list.append(h('li', { class: 'small' }, roleCan(state.user.role, 'write') ? 'Nothing here yet. Write something in the Write tab.' : 'Nothing to review yet.'));
  for (const it of items) {
    list.append(h('li', {}, h('button', { type: 'button', 'aria-current': state.detail && state.detail.id === it.id ? 'true' : 'false', onclick: () => openDetail(it.id) },
      h('strong', {}, it.title),
      h('span', { class: 'meta' }, h('span', {}, it.author_name), h('span', { class: `badge ${it.status}` }, STATUS_LABELS[it.status])))));
  }
  if (state.detail) { try { await openDetail(state.detail.id); } catch { state.detail = null; } }
  else if (!clear($('detail')).firstChild) $('detail').append(h('p', { class: 'muted' }, items.length ? 'Choose an item to read it, see its notes and decide.' : ''));
}

function selectionOffsets(container) {
  const sel = window.getSelection();
  if (!sel || sel.rangeCount === 0 || sel.isCollapsed) return null;
  const range = sel.getRangeAt(0);
  if (!container.contains(range.startContainer) || !container.contains(range.endContainer)) return null;
  const pre = document.createRange();
  pre.selectNodeContents(container);
  pre.setEnd(range.startContainer, range.startOffset);
  const startJs = pre.toString().length;
  const endJs = startJs + range.toString().length;
  const text = container.textContent;
  return { start: jsToCp(text, startJs), end: jsToCp(text, endJs), quote: range.toString() };
}

async function openDetail(id) {
  const c = await api('GET', `/api/content/${id}`);
  state.detail = c;
  for (const b of document.querySelectorAll('#queueList button')) b.setAttribute('aria-current', 'false');
  renderDetail(c);
  loadQueueHighlight(id);
}

function loadQueueHighlight(id) {
  const items = document.querySelectorAll('#queueList button');
  items.forEach((b) => { if (b.textContent.includes(state.detail.title) && state.detail.id === id) b.setAttribute('aria-current', 'true'); });
}

function renderDetail(c) {
  const box = clear($('detail'));
  const review = c.latest.review;
  const flags = review ? flagsToJs(c.latest.text, review.flags) : [];
  const mine = c.author_id === state.user.id;
  const ro = h('div', { class: 'readonly-text', id: 'ro', tabindex: 0, 'aria-label': 'Draft text' });
  for (const s of buildSegments(c.latest.text, flags)) {
    ro.append(s.severity ? h('span', { class: `mark sev-${s.severity}` }, s.text) : document.createTextNode(s.text));
  }
  add(box,
    h('div', {}, h('h2', {}, c.title),
      h('p', { class: 'small' }, `By ${c.author_name} · version ${c.latest.n} · `, h('span', { class: `badge ${c.status}` }, STATUS_LABELS[c.status]))),
    mine && roleCan(state.user.role, 'write') ? h('div', {}, h('button', { type: 'button', class: 'btn', onclick: async () => { applyContent(c); await setTab('write'); } }, 'Open in editor')) : null,
    h('div', {}, h('div', { class: 'sub' }, 'Draft (select text to comment on it)'), ro));

  if (review && review.claims.length) {
    box.append(h('div', {}, h('div', { class: 'sub' }, 'Claims and the Claim Ledger'),
      ...review.claims.map((cl) => h('span', { class: `claim ${cl.verdict}`, title: cl.detail }, h('b', {}, cl.verdict), `“${cl.text}”`))));
  }
  const notes = h('ol', { class: 'note-list' });
  for (const f of flags) notes.append(h('li', {}, noteCard(f, { readOnly: true })));
  box.append(h('div', {}, h('div', { class: 'sub' }, `Notes at the last check (${flags.length})`), flags.length ? notes : h('p', { class: 'muted' }, 'No notes.')));

  if (c.decisions.length) {
    const ruleTitle = (id) => ((state.kb.rules.find((r) => r.id === id)) || {}).title || '';
    const describe = (d) => {
      const rule = `${d.rule_id} ${ruleTitle(d.rule_id)}`.trim();
      if (d.action === 'accepted') return `Accepted a fix for ${rule} (${d.reason})`;
      if (d.action === 'overridden') return `Reviewer overrode ${rule}: “${d.reason}”`;
      return `Dismissed ${rule}: “${d.reason}”`;
    };
    box.append(h('div', {}, h('div', { class: 'sub' }, 'Decisions on notes'), ...c.decisions.map((d) => h('p', { class: 'small' }, describe(d)))));
  }

  if (c.versions.length > 1) {
    const from = h('select', { 'aria-label': 'From version' }); const to = h('select', { 'aria-label': 'To version' });
    for (const v of c.versions) { from.append(h('option', { value: v.n }, `v${v.n}`)); to.append(h('option', { value: v.n }, `v${v.n}`)); }
    from.value = String(c.versions[0].n); to.value = String(c.versions[c.versions.length - 1].n);
    const out = h('div', { class: 'diff', hidden: true });
    box.append(h('div', {}, h('div', { class: 'sub' }, 'Changes between versions'),
      h('div', { class: 'row' }, from, ' to ', to, ' ', h('button', { type: 'button', class: 'btn', onclick: async () => {
        try {
          const { ops } = await api('GET', `/api/content/${c.id}/diff?from=${from.value}&to=${to.value}`);
          clear(out).hidden = false;
          for (const p of diffParts(ops)) out.append(p.kind === 'same' ? document.createTextNode(p.text) : h('span', { class: p.kind }, p.text));
        } catch (e) { toast(e.message, 'error'); }
      } }, 'Show changes')), out));
  }

  const commentList = h('div', {});
  for (const cm of c.comments) {
    commentList.append(h('div', { class: `comment ${cm.resolved ? 'resolved' : ''}` },
      cm.end > cm.start ? h('q', {}, [...c.latest.text].slice(cm.start, cm.end).join('').slice(0, 80)) : null, h('div', {}, cm.body),
      cm.resolved ? h('span', { class: 'small' }, 'Resolved') : h('button', { type: 'button', class: 'link', onclick: async () => { await api('POST', `/api/content/${c.id}/comments/${cm.id}/resolve`, {}); openDetail(c.id); } }, 'Resolve')));
  }
  const cta = h('textarea', { 'aria-label': 'Comment', placeholder: 'Add a comment. Select text above first to anchor it.' });
  box.append(h('div', { class: 'comment-form' }, h('div', { class: 'sub' }, `Comments (${c.comments.length})`), commentList, cta,
    h('div', {}, h('button', { type: 'button', class: 'btn', onclick: async () => {
      const sel = selectionOffsets(ro) || { start: 0, end: 0 };
      try { await api('POST', `/api/content/${c.id}/comments`, { start: sel.start, end: sel.end, body: cta.value }); openDetail(c.id); } catch (e) { toast(e.message, 'error'); }
    } }, 'Add comment'))));

  if (roleCan(state.user.role, 'review') && c.status === 'in_review' && !mine) box.append(decisionPanel(c));
  else if (roleCan(state.user.role, 'review') && c.status === 'in_review' && mine) box.append(h('p', { class: 'small' }, 'You wrote this, so someone else must review it.'));

  if (c.receipts.length) {
    const wrap = h('div', {}, h('div', { class: 'sub' }, 'Receipts'));
    box.append(wrap);
    c.receipts.forEach(async (r) => { try { wrap.append(await receiptCard(r.id)); } catch { /* skip */ } });
  }
}

function decisionPanel(c) {
  const panel = h('div', { class: 'decision' }, h('div', { class: 'sub' }, 'Your decision'));
  const comment = h('textarea', { 'aria-label': 'Decision comment', placeholder: 'Comment (required for conditions or changes)' });
  const blockersBox = h('div', { hidden: true });
  const send = async (action, overrides) => {
    try {
      const out = await api('POST', `/api/content/${c.id}/review`, { action, comment: comment.value, overrides });
      toast(out.status === 'changes_requested' ? 'Changes requested.' : `Decision recorded: ${STATUS_LABELS[out.status]}. Receipt issued.`);
      if (out.receipt) state.openedReceipt = false;
      await loadQueue(); renderGuide();
      refreshOutChip();
    } catch (e) {
      if (e.code === 'blockers_open') showBlockers(action, e.data.error.unresolved_blockers);
      else toast(e.message, 'error');
    }
  };
  const showBlockers = (action, blockers) => {
    clear(blockersBox).hidden = false;
    const inputs = [];
    blockersBox.append(h('div', { class: 'blockers-open' },
      h('strong', {}, `${blockers.length} blocking issue(s) are still open.`),
      h('p', { class: 'small' }, 'You can fix them, or override each one with a written reason. Overrides are recorded on the receipt and feed Guideline Health.'),
      ...blockers.map((b) => {
        const input = h('input', { type: 'text', 'aria-label': `Override reason for ${b.text}`, placeholder: 'Reason (min. 10 characters)', maxlength: 300 });
        inputs.push([b.id, input]);
        return h('div', { class: 'item' }, h('span', {}, `${b.rule_id} · “${b.text}”`), input);
      }),
      h('div', {}, h('button', { type: 'button', class: 'btn warn', onclick: () => {
        const overrides = inputs.map(([flag_id, input]) => ({ flag_id, reason: input.value }));
        if (overrides.some((o) => o.reason.trim().length < 10)) { toast('Each override needs a reason of at least 10 characters.', 'error'); return; }
        send(action, overrides);
      } }, 'Approve with these overrides'))));
  };
  panel.append(comment, blockersBox, h('div', { class: 'row' },
    h('button', { type: 'button', class: 'btn ok', onclick: () => send('approve') }, 'Approve'),
    h('button', { type: 'button', class: 'btn', onclick: () => send('approve_with_conditions') }, 'Approve with conditions'),
    h('button', { type: 'button', class: 'btn warn', onclick: () => send('request_changes') }, 'Request changes')));
  return panel;
}

/* ---------------------------------------------------------------- insights, trust, status */
async function loadInsights() {
  const data = await api('GET', '/api/insights');
  const box = clear($('insightsBody'));
  const rows = data.rules.map((r) => h('tr', {},
    h('td', {}, h('strong', {}, `${r.rule_id}`), ' ', r.title),
    h('td', { class: 'num' }, String(r.shown)), h('td', { class: 'num' }, String(r.accepted)),
    h('td', { class: 'num' }, String(r.dismissed)), h('td', { class: 'num' }, String(r.overridden)),
    h('td', { class: 'num' }, percent(r.dispute_rate)),
    h('td', {}, h('span', { class: `tag ${r.status}` }, r.status === 'unclear' ? 'Possibly unclear' : r.status === 'healthy' ? 'Healthy' : 'Not enough data'))));
  box.append(h('table', { class: 'table' },
    h('thead', {}, h('tr', {}, h('th', {}, 'Rule'), h('th', { class: 'num' }, 'Flagged'), h('th', { class: 'num' }, 'Accepted'),
      h('th', { class: 'num' }, 'Dismissed'), h('th', { class: 'num' }, 'Overridden'), h('th', { class: 'num' }, 'Disputed'), h('th', {}, 'Health'))),
    h('tbody', {}, rows)),
  h('p', { class: 'small' }, `A rule is marked “possibly unclear” once it has been flagged at least ${data.min_samples} times and ${Math.round(data.dispute_threshold * 100)}% or more of those were dismissed or overridden.`));
  const statuses = Object.entries(data.content_by_status);
  box.append(h('div', { class: 'panel' }, h('div', { class: 'sub' }, 'Content by status'),
    statuses.length ? h('p', {}, statuses.map(([k, n]) => `${STATUS_LABELS[k]}: ${n}`).join(' · ')) : h('p', { class: 'muted' }, 'No content yet.')));
}

async function loadTrust() {
  const flow = await api('GET', '/api/dataflow');
  const x = clear($('xray'));
  x.append(h('div', { class: 'panel' },
    h('div', {}, h('div', { class: 'big' }, formatBytes(flow.external_bytes_sent)), h('div', { class: 'muted' }, 'sent to any external service so far')),
    h('p', {}, flow.ai.enabled
      ? `Model: ${flow.ai.provider} / ${flow.ai.model}. Personal data is masked before anything is sent; the entries below show exactly what a model saw.`
      : 'No model is configured, so exact checks run locally and no text leaves this system.'),
    ...(flow.entries.length ? flow.entries.slice().reverse().map((e) => h('div', {},
      h('p', { class: 'small' }, `${e.at} · ${e.provider} · ${e.external ? 'EXTERNAL' : 'local, not sent outside'} · ${e.redactions} item(s) masked · ${formatBytes(e.bytes)}`),
      h('pre', { class: 'payload' }, e.payload.length > 1500 ? `${e.payload.slice(0, 1500)}\n…` : e.payload))) : [h('p', { class: 'muted' }, 'No model calls yet.')])));
  const a = clear($('auditBody'));
  if (!roleCan(state.user.role, 'audit')) { a.append(h('p', { class: 'muted' }, 'The audit trail is visible to reviewers, managers and admins.')); return; }
  const audit = await api('GET', '/api/audit');
  a.append(h('p', {}, audit.chain_intact ? h('span', { class: 'audit-ok' }, '✓ Hash chain intact: no entry has been altered or removed.')
    : h('span', { class: 'audit-bad' }, `✗ Chain broken at entry ${audit.first_bad_seq}.`)),
  h('table', { class: 'table' },
    h('thead', {}, h('tr', {}, h('th', { class: 'num' }, '#'), h('th', {}, 'When'), h('th', {}, 'Who'), h('th', {}, 'Action'), h('th', {}, 'Hash'))),
    h('tbody', {}, audit.entries.slice().reverse().map((e) => h('tr', {}, h('td', { class: 'num' }, String(e.seq)), h('td', {}, e.ts), h('td', {}, e.actor), h('td', {}, e.action), h('td', { class: 'hash' }, e.hash.slice(0, 12)))))));
}

function renderAbout() {
  const s = state.status;
  const box = clear($('aboutBody'));
  const label = { built: 'Built', partial: 'Partly built', planned: 'Planned' };
  box.append(h('h2', { class: 'section-title' }, 'What is built, and what is planned'),
    h('p', { class: 'lead small-lead' }, `${s.counts.built || 0} built · ${s.counts.partial || 0} partly built · ${s.counts.planned || 0} planned. This list is generated by the server, so it cannot drift from the code.`),
    h('table', { class: 'table' }, h('thead', {}, h('tr', {}, h('th', {}, 'Capability'), h('th', {}, 'Status'), h('th', {}, 'Notes'))),
      h('tbody', {}, s.features.map((f) => h('tr', {}, h('td', {}, h('strong', {}, f.name)), h('td', {}, h('span', { class: `tag ${f.status}` }, label[f.status])), h('td', {}, f.note))))),
    h('h2', { class: 'section-title' }, 'Three planned improvements'),
    h('div', { class: 'cards' }, s.round3.map((r, i) => h('div', { class: 'card' }, h('h3', {}, `${i + 1}. ${r.title}`),
      h('p', {}, r.why), h('p', { class: 'small' }, r.scope), h('p', { class: 'done' }, `Done when: ${r.done_when}`)))));
}

/* ---------------------------------------------------------------- wiring */
function initControls() {
  const ta = $('text');
  ta.addEventListener('input', () => {
    state.text = ta.value; state.stale = true;
    renderMarks(); renderStatusBits(); renderNotes(); renderGuide();
    scheduleReview();
  });
  ta.addEventListener('scroll', () => { $('backdrop').scrollTop = ta.scrollTop; });
  $('save').addEventListener('click', save);
  $('submit').addEventListener('click', submitForReview);
  $('loadSample').addEventListener('click', loadSample);
  $('newDraft').addEventListener('click', () => { resetEditor(); renderWrite(); });
  $('simulate').addEventListener('change', (ev) => { state.simulate = ev.target.checked; if (state.text.trim()) { state.stale = true; renderEditor(); liveReview(); } });
  $('signOut').addEventListener('click', () => signOut(false));
  for (const b of document.querySelectorAll('#tabs button')) b.addEventListener('click', () => setTab(b.dataset.tab));
  $('checkContrast').addEventListener('click', async () => {
    const out = $('contrastOut');
    try {
      const r = await api('POST', '/api/contrast', { fg: $('fg').value, bg: $('bg').value, large: $('large').checked });
      out.textContent = `Contrast ${r.ratio}:1. AA ${r.aa ? 'pass' : 'fail'} (needs ${r.aa_minimum}:1), AAA ${r.aaa ? 'pass' : 'fail'}.${r.suggested_foreground ? ` Nearest passing text colour: ${r.suggested_foreground}.` : ''}`;
    } catch (e) { out.textContent = e.message; }
  });
}

async function init() {
  initControls();
  try { state.status = await api('GET', '/api/status'); } catch { /* login screen still works */ }
  if (state.token) {
    try { await enterApp(); return; } catch { state.token = null; sessionStorage.removeItem('bg_token'); }
  }
  await showLogin();
}

init();
