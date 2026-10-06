import test from 'node:test';
import assert from 'node:assert/strict';
import { read, load, core } from './load.js';

const { MESSAGES, HELP, t } = load('js/messages.js').PsvMessages;
const C = core();
const JAPANESE = new RegExp('[' + [[0x3000, 0x303f], [0x3040, 0x30ff], [0x3400, 0x9fff], [0xff00, 0xffef]]
  .map(([a, b]) => String.fromCharCode(a) + '-' + String.fromCharCode(b)).join('') + ']');
const placeholders = (s) => [...s.matchAll(/\{([a-zA-Z0-9]+)\}/g)].map((m) => m[1]).sort();

test('日本語と英語の辞書は同じキーを持ち、置き場所 {name} と太字の数もそろう', () => {
  assert.deepEqual(Object.keys(MESSAGES.en).sort(), Object.keys(MESSAGES.ja).sort());
  assert.ok(Object.keys(MESSAGES.ja).length >= 80, String(Object.keys(MESSAGES.ja).length));
  for (const k of Object.keys(MESSAGES.ja)) {
    assert.deepEqual([...new Set(placeholders(MESSAGES.en[k]))], [...new Set(placeholders(MESSAGES.ja[k]))], k);
    for (const lang of ['ja', 'en']) assert.equal((MESSAGES[lang][k].match(/\*\*/g) || []).length % 2, 0, `${lang} ${k}`);
  }
});

test('英語の辞書に日本語の文字がない（言語の切り替えボタンを除く）', () => {
  for (const [k, v] of Object.entries(MESSAGES.en)) {
    if (k === 'ui.langButton' || k === 'ui.langLabel') continue;
    assert.doesNotMatch(v, JAPANESE, k);
  }
});

test('日本語の文言は、日本語と英数字（インラインコードを含む）のあいだに半角空白を入れない。長音をそろえ、「わかる」はひらがな', () => {
  const bad = new RegExp(`(${JAPANESE.source} [A-Za-z0-9(\`])|([A-Za-z0-9)\`] ${JAPANESE.source})`);
  for (const [k, v] of Object.entries(MESSAGES.ja)) {
    assert.doesNotMatch(v, bad, k);
    assert.doesNotMatch(v, /ブラウザ(?!ー)|フォルダ(?!ー)|リポジトリ(?!ー)|ディレクトリ(?!ー)|サーバ(?!ー)|エディタ(?!ー)|ユーザ(?!ー)|パスワ(?!ー)|スキャナ(?!ー)|コンピュータ(?!ー)/, k);
    assert.doesNotMatch(v, /(?<![自0-9０-９])分か(?!れ)/, k);
    assert.doesNotMatch(v, /全て|もっとも|復号化/, k);
  }
});

test('一次資料に合う言い方（RFC 793 非準拠・ICMP type 3/code 3・ステルスの注記）', () => {
  const ja = MESSAGES.ja;
  const en = MESSAGES.en;
  // FIN/NULL/Xmas は RFC 793 に準拠しないスタック（Windows だけでなく）で判定できない
  for (const id of ['fin', 'null', 'xmas']) {
    assert.match(ja[`scan.${id}.cons`], /RFC 793/, id);
    assert.match(ja[`scan.${id}.cons`], /判定できない/, id);
  }
  assert.match(ja['scan.fin.cons'], /Windows・一部Cisco・BSDI・OS\/400/);
  assert.match(en['scan.fin.cons'], /Windows, some Cisco, BSDI, OS\/400/);
  // UDP の閉は ICMP Port Unreachable（type 3, code 3）
  assert.match(ja['f.icmpUnreach'], /type 3, code 3/);
  assert.match(ja['scan.udp.summary'], /type 3, code 3/);
  // SYN の「ステルス」は歴史的な呼称で、現代の IDS では検知されうる
  assert.match(ja['scan.tcp-syn.ids'], /現代のIDS\/IPS/);
  assert.match(ja['scan.tcp-syn.ids'], /歴史的な呼称/);
  assert.match(en['scan.tcp-syn.ids'], /historical name/);
  // 特権の要否（Connect は不要、ほかは必要）
  assert.match(ja['scan.tcp-connect.priv'], /不要/);
  for (const id of ['tcp-syn', 'fin', 'null', 'xmas', 'udp']) assert.match(ja[`scan.${id}.priv`], /特権が必要/, id);
});

test('画面が使う文言のキー（手法×項目・フレーム・判定・検知）は、すべて日英の辞書にある', () => {
  const keys = new Set();
  for (const id of C.SCAN_IDS) for (const s of ['name', 'summary', 'pros', 'cons', 'priv', 'ids']) keys.add(`scan.${id}.${s}`);
  for (const id of C.SCAN_IDS) for (const state of ['open', 'closed']) for (const f of C.getFrames(id, state)) keys.add(f.descKey);
  for (const j of ['open', 'closed', 'openFiltered', 'pending']) keys.add(`judge.${j}`);
  for (const d of ['high', 'medium', 'low']) keys.add(`det.${d}`);
  // app.js に literal で書いた t('…') のキーも
  for (const m of read('js/app.js').matchAll(/\bt\('([a-zA-Z0-9.]+)'/g)) keys.add(m[1]);
  assert.ok(keys.size >= 60, String(keys.size));
  for (const k of keys) for (const lang of ['ja', 'en']) assert.ok(MESSAGES[lang][k] !== undefined, `${lang} ${k}`);
});

test('ヘルプの組み立てが使うキーは、すべて日英の辞書にある', () => {
  for (const item of HELP) for (const k of item.keys || [item.key]) {
    for (const lang of ['ja', 'en']) assert.ok(MESSAGES[lang][k] !== undefined, `${lang} ${k}`);
  }
});

test('t は {name} を置き換え、ない鍵はキーをそのまま返す', () => {
  assert.equal(t('judge.open', {}, 'en'), 'Open');
  assert.equal(t('det.high', {}, 'ja'), '高い');
  assert.equal(t('no.such.key', {}, 'ja'), 'no.such.key');
});
