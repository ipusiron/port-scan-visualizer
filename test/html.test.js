import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { read, load, core } from './load.js';

const html = read('index.html');
const C = core();
const { MESSAGES, HELP, t } = load('js/messages.js').PsvMessages;
const SCRIPTS = ['js/theme-init.js', 'js/psv-core.js', 'js/messages.js', 'js/i18n.js', 'js/theme.js', 'js/app.js'];
const ids = new Set([...html.matchAll(/\sid="([^"]+)"/g)].map((m) => m[1]));

test('CSP はスクリプト・スタイルを同じ場所のファイルだけに限り、unsafe-inline と外部の通信を許さない', () => {
  const csp = html.match(/http-equiv="Content-Security-Policy" content="([^"]+)"/)[1];
  assert.equal(csp, "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    + "connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'");
  // meta に書いても効かない X-Frame-Options・X-Content-Type-Options・frame-ancestors は置かない
  assert.doesNotMatch(html, /X-Content-Type-Options|X-Frame-Options|frame-ancestors|unsafe-inline/i);
  assert.match(html, /<meta name="referrer" content="no-referrer" \/>/);
  assert.match(html, /<link rel="icon" href="data:," \/>/);
  assert.match(html, /<noscript>/);
});

test('外部のスクリプトを読まない。style 属性・インラインのスクリプト・イベントハンドラーがない。旧 script.js は残さない', () => {
  assert.doesNotMatch(html, /\sstyle=/);
  assert.doesNotMatch(html, /\son[a-z]+=/i);
  const scripts = [...html.matchAll(/<script src="([^"]+)"><\/script>/g)].map((m) => m[1]);
  assert.deepEqual(scripts, SCRIPTS);
  assert.equal((html.match(/<script/g) || []).length, scripts.length);
  assert.doesNotMatch(html, /cdn\.|jsdelivr|unpkg|http:\/\/|https:\/\/[^"]*\.js/i);
  for (const a of html.match(/<a [^>]*>/g) || []) assert.match(a, /target="_blank" rel="noopener noreferrer"/, a);
  const js = fs.readdirSync(new URL('../js', import.meta.url)).map((f) => `js/${f}`).sort();
  assert.deepEqual(js, [...SCRIPTS].sort());
  assert.equal(fs.existsSync(new URL('../script.js', import.meta.url)), false);
  assert.equal(fs.existsSync(new URL('../js/script.js', import.meta.url)), false);
});

test('ヘルプのモーダルは role="dialog"・aria-modal・aria-labelledby を持ち、閉じるボタンに名前がある', () => {
  const modal = html.match(/<div id="helpModal"[^>]*>/)[0];
  assert.match(modal, /\shidden/);
  const box = html.match(/<div class="modal-box"[^>]*>/)[0];
  assert.match(box, /role="dialog"/);
  assert.match(box, /aria-modal="true"/);
  assert.match(box, /aria-labelledby="helpTitle"/);
  assert.ok(ids.has('helpTitle'));
  assert.match(html, /id="closeModal"[^>]*aria-label="[^"]+"/);
});

test('ボタンは type="button"。select と number 入力には label、チェックボックスは aria で名前がある', () => {
  for (const b of html.match(/<button[^>]*>/g)) assert.match(b, /type="button"/, b);
  for (const tag of html.match(/<(?:input|select) [^>]*>/g)) {
    const id = (tag.match(/\sid="([^"]+)"/) || [])[1];
    if (!id) continue;
    if (/type="checkbox"/.test(tag)) { assert.match(tag, /aria-labelledby="[^"]+"/, id); continue; }
    assert.match(html, new RegExp(`<label [^>]*for="${id}"`), id);
  }
  // number 入力には inputmode="numeric"（数字キーボード）
  assert.equal((html.match(/<input [^>]*type="number"/g) || []).length, (html.match(/inputmode="numeric"/g) || []).length);
});

test('知らせの欄（判定バッジ・時系列）に aria-live がある', () => {
  for (const id of ['judgementBadge', 'timelineList']) assert.match(html, new RegExp(`id="${id}"[^>]*aria-live="polite"`), id);
});

// 文言の太字（**）は HTML の strong に当たる。HTML 側のタグを外して比べる
const plain = (s) => s.replace(/\n\s*/g, '').replace(/<[^>]+>/g, '')
  .replace(/&gt;/g, '>').replace(/&lt;/g, '<').replace(/&quot;/g, '"').replace(/&#x27;/g, "'").replace(/&amp;/g, '&').trim();
const fromDict = (s) => s.replace(/\*\*/g, '');

test('data-i18n のキーは辞書にあり、HTML に書いた日本語は辞書の日本語と同じ（属性も）', () => {
  let n = 0;
  for (const m of html.matchAll(/<([a-z0-9]+)([^>]*?)data-i18n="([^"]+)"([^>]*)>([\s\S]*?)<\/\1>/g)) {
    const key = m[3];
    assert.ok(MESSAGES.ja[key] !== undefined, key);
    assert.equal(plain(m[5]), fromDict(MESSAGES.ja[key]), key);
    n++;
  }
  assert.ok(n >= 20, String(n));
  for (const m of html.matchAll(/<[^>]*data-i18n-attr="([^"]+)"[^>]*>/g)) {
    for (const pair of m[1].split(';')) {
      const [attr, key] = pair.split(':');
      assert.ok(MESSAGES.ja[key] !== undefined, pair);
      const v = m[0].match(new RegExp(`\\s${attr}="([^"]*)"`));
      assert.ok(v && plain(v[1]) === MESSAGES.ja[key], pair);
    }
  }
});

test('画面のスクリプトが参照する id は、すべて HTML にある', () => {
  const src = read('js/app.js');
  const used = new Set([...src.matchAll(/\$\('([a-zA-Z0-9-]+)'\)/g)].map((m) => m[1]));
  assert.ok(used.size >= 15, String(used.size));
  for (const id of used) assert.ok(ids.has(id), id);
});

test('ヘルプの中身の組み立てが使うキーは、すべて辞書にある', () => {
  for (const item of HELP) for (const k of item.keys || [item.key]) {
    for (const lang of ['ja', 'en']) assert.ok(MESSAGES[lang][k] !== undefined, `${lang} ${k}`);
  }
});

test('JS は innerHTML・eval・fetch・console を使わず、style を直接書き換えない', () => {
  for (const f of SCRIPTS) {
    const src = read(f);
    assert.doesNotMatch(src, /innerHTML|outerHTML|insertAdjacentHTML|DOMParser|\beval\(|new Function|document\.write/, f);
    assert.doesNotMatch(src, /console\.(log|debug|info|error|warn)/, f);
    assert.doesNotMatch(src, /sessionStorage|fetch\(|XMLHttpRequest|WebSocket|sendBeacon/, f);
    assert.doesNotMatch(src, /\.style\./, f);
  }
});

test('localStorage は try で囲んで読み書きする（使えない環境でも画面が止まらない）', () => {
  let total = 0;
  for (const f of SCRIPTS) {
    const src = read(f);
    const uses = (src.match(/localStorage\./g) || []).length;
    const guarded = [...src.matchAll(/try \{\s*(?:const [a-z]+ = |return )?localStorage\./g)].length;
    assert.equal(guarded, uses, f);
    total += uses;
  }
  assert.equal(total, 4);
});
