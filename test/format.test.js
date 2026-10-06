import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { read } from './load.js';

const list = (dir, ext) => fs.readdirSync(new URL(`../${dir}`, import.meta.url)).filter((f) => f.endsWith(ext)).map((f) => `${dir}/${f}`);
const CODE = [...list('js', '.js'), ...list('test', '.js'), 'style.css'];

// ソースのコード行は160字まで。辞書の解説文（messages.js）とテストの assertion 行、index.html は長くなるので別枠
const LIMIT = (f) => (f === 'js/messages.js' ? 360 : f.startsWith('test/') ? 260 : f === 'index.html' ? 250 : 160);

test('最長行の制限（コードは160字、messages.js の辞書は360字、テストは260字、index.html は250字）', () => {
  for (const f of [...CODE, 'index.html']) {
    const max = LIMIT(f);
    const i = read(f).split('\n').findIndex((l) => [...l].length > max);
    assert.equal(i, -1, `${f}:${i + 1} (>${max})`);
  }
});

test('主要なファイルは1行に詰め込まれていない（行数の下限）', () => {
  const min = { 'js/psv-core.js': 120, 'js/messages.js': 200, 'js/app.js': 300, 'style.css': 280, 'index.html': 130 };
  for (const [f, n] of Object.entries(min)) assert.ok(read(f).split('\n').length >= n, `${f}: ${read(f).split('\n').length}`);
});

test('改行は LF、制御文字なし、末尾に改行', () => {
  for (const f of [...CODE, 'index.html', 'package.json', '.github/workflows/test.yml']) {
    const s = read(f);
    assert.ok(!s.includes('\r'), `${f}: CR`);
    assert.ok(![...s].some((ch) => { const c = ch.codePointAt(0); return (c < 32 && c !== 10) || c === 127; }), f);
    assert.ok(s.endsWith('\n'), `${f}: no final newline`);
  }
});
