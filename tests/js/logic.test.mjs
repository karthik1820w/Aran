import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildSegments, applyLocalEdit, parseNdjson, debounce, diffParts, issueLabel, suggestionLabel, isApplicable,
  roleCan, nextStep, formatBytes, percent, worstSeverity, STATUS_LABELS, cpToJs, jsToCp, flagsToJs, countBlockers,
} from '../../brandguardian/web/logic.js';

const flag = (id, start, end, severity = 'warning') => ({ id, start, end, severity });

test('buildSegments covers the whole text without gaps or overlaps', () => {
  const text = 'Our clients love NovaBar.';
  const segs = buildSegments(text, [flag('a', 4, 11), flag('b', 17, 24, 'blocker')]);
  assert.equal(segs.map((s) => s.text).join(''), text);
  assert.deepEqual(segs.map((s) => [s.start, s.end]), [[0, 4], [4, 11], [11, 17], [17, 24], [24, 25]]);
  assert.deepEqual(segs.map((s) => s.severity), [null, 'warning', null, 'blocker', null]);
});

test('buildSegments handles overlapping flags and keeps the worst severity', () => {
  const segs = buildSegments('abcdefgh', [flag('a', 0, 6, 'info'), flag('b', 3, 8, 'blocker')]);
  assert.equal(segs.map((s) => s.text).join(''), 'abcdefgh');
  const middle = segs.find((s) => s.start === 3);
  assert.deepEqual(middle.flagIds, ['a', 'b']);
  assert.equal(middle.severity, 'blocker');
});

test('buildSegments ignores invalid ranges and handles empty input', () => {
  assert.deepEqual(buildSegments('', []), []);
  const segs = buildSegments('hello', [flag('x', -1, 3), flag('y', 3, 3), flag('z', 2, 99), { id: 'q' }]);
  assert.equal(segs.length, 1);
  assert.equal(segs[0].severity, null);
});

test('offset conversion between code points and UTF-16 units', () => {
  const text = '😀 clients';
  assert.equal(text.length, 10);
  assert.equal(cpToJs(text, 2), 3); // after the emoji and the space
  assert.equal(jsToCp(text, 3), 2);
  assert.equal(text.slice(cpToJs(text, 2), cpToJs(text, 9)), 'clients');
  assert.equal(cpToJs('plain', 3), 3);
  assert.equal(cpToJs('abc', 99), 3);
  for (let i = 0; i <= [...text].length; i += 1) assert.equal(jsToCp(text, cpToJs(text, i)), i);
});

test('flagsToJs realigns server flags for astral text and leaves plain text alone', () => {
  const text = '😀 clients love it';
  const serverFlags = [{ id: 'a', start: 2, end: 9, severity: 'warning', suggestions: [{ action: 'replace', text: 'customers', start: null, end: null }] }];
  const [fixed] = flagsToJs(text, serverFlags);
  assert.equal(text.slice(fixed.start, fixed.end), 'clients');
  assert.equal(fixed.suggestions[0].start, null);
  const plain = [{ id: 'b', start: 1, end: 2, suggestions: [] }];
  assert.equal(flagsToJs('abc', plain), plain);
  const segs = buildSegments(text, [fixed]);
  assert.equal(segs.map((s) => s.text).join(''), text);
});

test('countBlockers', () => {
  assert.equal(countBlockers([{ severity: 'blocker' }, { severity: 'info' }, { severity: 'blocker' }]), 2);
  assert.equal(countBlockers(undefined), 0);
});

test('applyLocalEdit replaces, deletes and tidies spaces', () => {
  const f = { start: 4, end: 11 };
  assert.equal(applyLocalEdit('Our clients love it.', f, { action: 'replace', text: 'customers' }), 'Our customers love it.');
  assert.equal(applyLocalEdit('We love the best snack bar here.', { start: 12, end: 26 }, { action: 'delete' }), 'We love the here.');
  assert.equal(applyLocalEdit('Buy now at the best snack bar.', { start: 15, end: 29 }, { action: 'delete' }), 'Buy now at the.');
  assert.equal(applyLocalEdit('x', f, { action: 'replace', text: 'y' }), null);
  assert.equal(applyLocalEdit('abc', f, { action: 'manual' }), null);
});

test('applyLocalEdit honours suggestion ranges that differ from the flag range', () => {
  const text = 'Each bar has 25 g of protein.';
  const out = applyLocalEdit(text, { start: 13, end: 28 }, { action: 'replace', text: '20', start: 13, end: 15 });
  assert.equal(out, 'Each bar has 20 g of protein.');
});

test('parseNdjson returns complete lines and keeps the remainder', () => {
  const first = parseNdjson('{"a":1}\n{"b":2}\n{"c"');
  assert.deepEqual(first.events, [{ a: 1 }, { b: 2 }]);
  assert.equal(first.rest, '{"c"');
  const second = parseNdjson(first.rest + ':3}\n');
  assert.deepEqual(second.events, [{ c: 3 }]);
  assert.equal(second.rest, '');
});

test('parseNdjson skips blank and malformed lines', () => {
  const { events } = parseNdjson('\n{"ok":true}\nnot json\n\n');
  assert.deepEqual(events, [{ ok: true }]);
});

test('debounce only fires the last call, and can be cancelled', () => {
  const queue = [];
  const timers = { set: (fn) => { queue.push(fn); return queue.length; }, clear: (h) => { queue[h - 1] = null; } };
  const seen = [];
  const d = debounce((v) => seen.push(v), 100, timers);
  d(1); d(2); d(3);
  queue.splice(0).forEach((fn) => fn && fn());
  assert.deepEqual(seen, [3]);
  d(4); d.cancel();
  queue.splice(0).forEach((fn) => fn && fn());
  assert.deepEqual(seen, [3]);
});

test('diffParts maps ops to display parts', () => {
  const parts = diffParts([{ op: 'equal', old: 'Our ', new: 'Our ' }, { op: 'replace', old: 'clients', new: 'customers' }, { op: 'insert', old: '', new: '!' }]);
  assert.deepEqual(parts, [
    { kind: 'same', text: 'Our ' }, { kind: 'removed', text: 'clients' }, { kind: 'added', text: 'customers' }, { kind: 'added', text: '!' },
  ]);
});

test('labels', () => {
  assert.equal(issueLabel('wrong_term'), 'Wrong term');
  assert.equal(issueLabel('some_new_kind'), 'Some new kind');
  assert.equal(issueLabel(undefined), 'Issue');
  assert.equal(suggestionLabel({ action: 'replace', text: 'customers' }), 'Replace with “customers”');
  assert.equal(suggestionLabel({ action: 'delete' }), 'Remove it');
  assert.equal(suggestionLabel({ action: 'request_evidence' }), 'Ask for evidence');
  assert.equal(suggestionLabel({ action: 'manual' }), 'Edit by hand');
  assert.ok(suggestionLabel({ action: 'replace', text: 'x'.repeat(100) }).length < 60);
  assert.equal(isApplicable({ action: 'manual' }), false);
  assert.equal(isApplicable({ action: 'delete' }), true);
  assert.equal(STATUS_LABELS.approved_with_conditions, 'Approved with conditions');
});

test('worstSeverity', () => {
  assert.equal(worstSeverity(['info', 'warning']), 'warning');
  assert.equal(worstSeverity(['info', 'blocker', 'warning']), 'blocker');
  assert.equal(worstSeverity([]), null);
  assert.equal(worstSeverity(['bogus']), null);
});

test('roleCan mirrors the server permission table', () => {
  assert.equal(roleCan('creator', 'write'), true);
  assert.equal(roleCan('admin', 'write'), false);
  assert.equal(roleCan('reviewer', 'review'), true);
  assert.equal(roleCan('creator', 'review'), false);
  assert.equal(roleCan('external', 'insights'), false);
  assert.equal(roleCan('admin', 'audit'), true);
  assert.equal(roleCan('x', 'nothing'), false);
});

test('nextStep walks the guided path', () => {
  assert.equal(nextStep({ signedIn: false }).index, 0);
  assert.equal(nextStep({ signedIn: true, role: 'creator', hasText: false }).index, 1);
  assert.equal(nextStep({ signedIn: true, role: 'creator', hasText: true, saved: false, blockers: 3 }).index, 2);
  assert.equal(nextStep({ signedIn: true, role: 'creator', hasText: true, saved: true, blockers: 2 }).index, 2);
  assert.equal(nextStep({ signedIn: true, role: 'creator', hasText: true, saved: true, blockers: 0, status: 'draft' }).index, 3);
  assert.equal(nextStep({ signedIn: true, role: 'creator', hasText: true, saved: true, status: 'in_review' }).index, 4);
  assert.equal(nextStep({ signedIn: true, role: 'reviewer', status: 'in_review' }).index, 4);
  assert.equal(nextStep({ signedIn: true, role: 'creator', hasReceipt: true }).index, 5);
});

test('formatting helpers', () => {
  assert.equal(formatBytes(0), '0 bytes');
  assert.equal(formatBytes(1), '1 byte');
  assert.equal(formatBytes(2048), '2.0 KB');
  assert.equal(formatBytes(-5), '0 bytes');
  assert.equal(percent(0.456), '46%');
  assert.equal(percent(null), '—');
});

test('debounce works with the real default timers called as methods of an object', async () => {
  const seen = [];
  const d = debounce((v) => seen.push(v), 10);
  d('a'); d('b');
  await new Promise((resolve) => setTimeout(resolve, 60));
  assert.deepEqual(seen, ['b']);
});
