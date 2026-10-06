import test from 'node:test';
import assert from 'node:assert/strict';
import { core } from './load.js';

const C = core();

test('6手法があり、順と id が合う。各手法に proto・open・closed がある', () => {
  assert.deepEqual(C.SCAN_IDS, ['tcp-connect', 'tcp-syn', 'fin', 'null', 'xmas', 'udp']);
  assert.deepEqual(Object.keys(C.SCANS).sort(), [...C.SCAN_IDS].sort());
  for (const id of C.SCAN_IDS) {
    const s = C.SCANS[id];
    assert.ok(['TCP', 'UDP'].includes(s.proto), id);
    for (const state of ['open', 'closed']) {
      assert.ok(Array.isArray(s[state].frames) && s[state].frames.length >= 2, `${id} ${state}`);
      assert.ok(['open', 'closed', 'openFiltered'].includes(s[state].judgement), `${id} ${state}`);
    }
  }
});

test('TCP Connect: 開＝SYN→SYN/ACK→ACK→FIN/ACK（判定 open）、閉＝SYN→RST/ACK（判定 closed）', () => {
  const o = C.getFrames('tcp-connect', 'open');
  assert.deepEqual(o.map(C.packetLabel), ['SYN', 'SYN+ACK', 'ACK', 'FIN+ACK']);
  assert.deepEqual(o.map((f) => f.dir), ['out', 'in', 'out', 'out']);
  assert.equal(C.getJudgement('tcp-connect', 'open'), 'open');
  const c = C.getFrames('tcp-connect', 'closed');
  assert.deepEqual(c.map(C.packetLabel), ['SYN', 'RST+ACK']);
  assert.equal(C.getJudgement('tcp-connect', 'closed'), 'closed');
});

test('TCP SYN（ハーフオープン）: 開＝SYN→SYN/ACK→RST で中断（SYN/ACK を受けたら RST）', () => {
  const o = C.getFrames('tcp-syn', 'open');
  assert.deepEqual(o.map(C.packetLabel), ['SYN', 'SYN+ACK', 'RST']);
  assert.deepEqual(o.map((f) => f.dir), ['out', 'in', 'out']);
  assert.equal(C.getJudgement('tcp-syn', 'open'), 'open');
});

test('FIN・NULL・Xmas: 開は無応答で open|filtered、閉は RST/ACK。送るフラグが手法どおり', () => {
  const send = { fin: 'FIN', null: 'NULL', xmas: 'FIN+PSH+URG' };
  for (const id of ['fin', 'null', 'xmas']) {
    const o = C.getFrames(id, 'open');
    assert.equal(C.packetLabel(o[0]), send[id], id);
    assert.equal(o[0].dir, 'out', id);
    assert.equal(o[1].dir, 'timeout', id);
    assert.equal(C.getJudgement(id, 'open'), 'openFiltered', id);
    const c = C.getFrames(id, 'closed');
    assert.equal(C.packetLabel(c[0]), send[id], id);
    assert.equal(C.packetLabel(c[1]), 'RST+ACK', id);
    assert.equal(C.getJudgement(id, 'closed'), 'closed', id);
  }
  // NULL はフラグなし
  assert.deepEqual(C.getFrames('null', 'open')[0].flags, []);
});

test('UDP: 開は無応答で open|filtered、閉は ICMP Port Unreachable（type 3, code 3）', () => {
  const o = C.getFrames('udp', 'open');
  assert.deepEqual([o[0].proto, C.packetLabel(o[0]), o[1].dir], ['UDP', 'UDP', 'timeout']);
  assert.equal(C.getJudgement('udp', 'open'), 'openFiltered');
  const c = C.getFrames('udp', 'closed');
  assert.equal(c[1].proto, 'ICMP');
  assert.deepEqual(c[1].icmp, { type: 3, code: 3 });
  assert.equal(C.packetLabel(c[1]), 'ICMP');
  assert.equal(C.getJudgement('udp', 'closed'), 'closed');
});

test('閉じたポートの応答は RST/ACK（RST だけでなく ACK も立つ。RFC 9293）', () => {
  for (const id of C.SCAN_IDS) {
    if (id === 'udp') continue;
    const last = C.getFrames(id, 'closed').at(-1);
    assert.ok(last.flags.includes('RST') && last.flags.includes('ACK'), id);
  }
});

test('プロトコル: UDP 手法だけ proto が UDP、ほかは TCP', () => {
  for (const id of C.SCAN_IDS) assert.equal(C.SCANS[id].proto, id === 'udp' ? 'UDP' : 'TCP', id);
});

test('IDS の検知性: Connect が high、SYN・Xmas が medium、FIN・NULL・UDP が low', () => {
  assert.deepEqual(C.DETECTABILITY, { 'tcp-connect': 'high', 'tcp-syn': 'medium', fin: 'low', null: 'low', xmas: 'medium', udp: 'low' });
  for (const v of Object.values(C.DETECTABILITY)) assert.ok(['high', 'medium', 'low'].includes(v));
});

test('ポートの検証: 1〜65535 の整数だけ通す。範囲外・空・小数・非数は ok:false', () => {
  assert.deepEqual(C.validatePort('80'), { ok: true, value: 80 });
  assert.deepEqual(C.validatePort('1'), { ok: true, value: 1 });
  assert.deepEqual(C.validatePort('65535'), { ok: true, value: 65535 });
  for (const bad of ['0', '65536', '-1', '', ' ', 'abc', '80.5', '08', '1e3']) assert.equal(C.validatePort(bad).ok, false, bad);
  assert.equal(C.DEFAULT_PORT, 80);
});

test('packetLabel: フラグの組・UDP・ICMP・NULL を正しく出す', () => {
  assert.equal(C.packetLabel({ proto: 'TCP', flags: ['SYN', 'ACK'] }), 'SYN+ACK');
  assert.equal(C.packetLabel({ proto: 'TCP', flags: [] }), 'NULL');
  assert.equal(C.packetLabel({ proto: 'UDP' }), 'UDP');
  assert.equal(C.packetLabel({ proto: 'ICMP', icmp: { type: 3, code: 3 } }), 'ICMP');
  assert.equal(C.packetLabel({ proto: 'TCP', dir: 'timeout' }), 'NULL');
});

test('TCP フラグの一覧は凡例の6種。unknown な手法は例外', () => {
  assert.deepEqual(C.TCP_FLAGS, ['SYN', 'ACK', 'FIN', 'PSH', 'URG', 'RST']);
  assert.throws(() => C.scenario('ack', 'open'), /unknown scan/);
});

test('RFC 793 非準拠: FIN/NULL/Xmas は開でも閉でも RST/ACK が返り判定できない', () => {
  assert.deepEqual([...C.NONCOMPLIANT_AFFECTED].sort(), ['fin', 'null', 'xmas']);
  for (const id of ['fin', 'null', 'xmas']) {
    assert.ok(C.affectedByCompliance(id), id);
    for (const state of ['open', 'closed']) {
      const f = C.getFrames(id, state, false);
      assert.equal(f.length, 2, `${id} ${state}`);
      assert.equal(f[0].dir, 'out', id); // 送るパケットは準拠時と同じ
      assert.equal(C.packetLabel(f[1]), 'RST+ACK', id);
      assert.equal(f[1].descKey, 'f.rstAckNoncompliant', id);
      assert.equal(C.getJudgement(id, state, false), 'undecidable', `${id} ${state}`);
    }
  }
});

test('RFC 793 非準拠は TCP Connect・SYN・UDP には影響しない（準拠と同じ）', () => {
  for (const id of ['tcp-connect', 'tcp-syn', 'udp']) {
    assert.equal(C.affectedByCompliance(id), false, id);
    for (const state of ['open', 'closed']) {
      assert.deepEqual(C.getFrames(id, state, false), C.getFrames(id, state, true), `${id} ${state}`);
      assert.equal(C.getJudgement(id, state, false), C.getJudgement(id, state, true), `${id} ${state}`);
    }
  }
  // 既定（compliant 省略）は準拠として扱う
  assert.equal(C.getJudgement('fin', 'open'), 'openFiltered');
  assert.equal(C.getJudgement('fin', 'open', false), 'undecidable');
});

test('フレームの descKey は、すべて f. で始まる（文言の辞書キー）', () => {
  for (const id of C.SCAN_IDS) {
    for (const state of ['open', 'closed']) {
      for (const f of C.getFrames(id, state)) assert.match(f.descKey, /^f\./, `${id} ${state}`);
    }
  }
});
