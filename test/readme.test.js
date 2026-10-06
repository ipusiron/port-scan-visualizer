import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { read, core } from './load.js';

const C = core();
const ROOT = fileURLToPath(new URL('..', import.meta.url));

const DOCS = {
  ja: {
    file: 'README.md', switcher: '[English](README.en.md) · 日本語', day: '**Day062 - 生成AIで作るセキュリティツール100**',
    h1: '# Port Scan Visualizer - ポートスキャン手法可視化ツール', shots: /^assets\/screenshot[\w-]*\.png$/,
    h2: ['🌐 デモページ', '📸 スクリーンショット', '✨ 特徴', '📖 使い方', '🔍 6種類のスキャン手法', '🛡️ IDSでの検知', '🎯 ユースケース',
      '🔬 技術的な説明', '🔒 セキュリティ', '⚠️ 注意と限界', '🧪 テスト', '🔗 参考文献', '📁 ディレクトリー構造', '💻 動作環境',
      '📄 ライセンス', '🛠 このツールについて'],
    facts: ['6種類', 'TCP Connect', 'TCP SYN', 'FIN', 'NULL', 'Xmas', 'UDP', 'RFC 793', 'Windows・一部Cisco・BSDI・OS/400',
      'ICMP Port Unreachable（type 3, code 3）', 'Open｜Filtered', '1〜65535'],
    forbidden: new RegExp(['ブラウザ(?!ー)', 'フォルダ(?!ー)', 'ディレクトリ(?!ー)', 'リポジトリ(?!ー)', 'サーバ(?!ー)', 'ユーザ(?!ー)',
      'パスワ(?!ー)', 'スキャナ(?!ー)', '(?<![自0-9０-９])分か(?!れ)', '全て', 'もっとも', '復号化', '完全網羅', '完全なセキュリティ', 'script\\.js'].join('|'))
  },
  en: {
    file: 'README.en.md', switcher: 'English · [日本語](README.md)', day: '**Day062 - 100 Security Tools with Generative AI**',
    h1: '# Port Scan Visualizer - Port Scanning Technique Visualizer', shots: /^assets\/en\/screenshot[\w-]*\.png$/,
    h2: ['🌐 Demo', '📸 Screenshots', '✨ Features', '📖 How to use', '🔍 The six scan methods', '🛡️ IDS detection', '🎯 Use cases',
      '🔬 Technical notes', '🔒 Security', '⚠️ Notes and limitations', '🧪 Tests', '🔗 References', '📁 Directory structure',
      '💻 Requirements', '📄 License', '🛠 About this tool'],
    facts: ['six port-scan methods', 'TCP Connect', 'TCP SYN', 'FIN', 'NULL', 'Xmas', 'UDP', 'RFC 793',
      'Windows, some Cisco, BSDI, OS/400', 'ICMP Port Unreachable (type 3, code 3)', 'Open|Filtered', '1-65535'],
    forbidden: /require complexity|ideal for embedded|\bscript\.js\b/i
  }
};
const PROJECT = 'https://akademeia.info/?page_id=42163';
for (const d of Object.values(DOCS)) d.text = read(d.file);

const noCode = (md) => md.replace(/```[\s\S]*?```/g, '');
const headings = (md) => noCode(md).split('\n').filter((l) => /^#{1,4} /.test(l));
const h2 = (md) => headings(md).filter((l) => l.startsWith('## ')).map((l) => l.slice(3));

function section(text, heading) {
  const i = text.indexOf(`\n## ${heading}\n`);
  assert.ok(i >= 0, heading);
  const rest = text.slice(i + 1);
  const end = rest.indexOf('\n## ', 3);
  return end < 0 ? rest : rest.slice(0, end);
}

test('YAML メタデータの構造（キーの順、ブロック形式のリスト、固定の値）。YAML は README.md だけに置く', () => {
  const m = DOCS.ja.text.match(/^<!--\n---\n([\s\S]*?)\n---\n-->\n/);
  assert.ok(m, 'YAML block');
  const keys = [...m[1].matchAll(/^([a-z_]+):/gm)].map((x) => x[1]);
  assert.deepEqual(keys, ['id', 'slug', 'title', 'subtitle_ja', 'subtitle_en', 'description_ja', 'description_en',
    'category_ja', 'category_en', 'difficulty', 'tags', 'repo_url', 'demo_url', 'hub']);
  for (const k of ['category_ja', 'category_en', 'tags']) assert.match(m[1], new RegExp(`^${k}:\\n  - `, 'm'), k);
  assert.match(m[1], /^id: day062$/m);
  assert.match(m[1], /^slug: port-scan-visualizer$/m);
  assert.match(m[1], /^repo_url: "https:\/\/github.com\/ipusiron\/port-scan-visualizer"$/m);
  assert.match(m[1], /^hub: true$/m);
  assert.doesNotMatch(DOCS.en.text, /^<!--\n---/);
});

test('冒頭の形（言語の切り替え・H1・バッジ5種・Dayの行）と、H2の並び。日英で見出しの数と階層がそろう', () => {
  for (const d of Object.values(DOCS)) {
    assert.ok(d.text.includes(`\n${d.switcher}\n`) || d.text.startsWith(`${d.switcher}\n`), d.file);
    assert.ok(d.text.includes(`\n${d.h1}\n`), d.file);
    assert.ok(d.text.includes(`\n${d.day}\n`), d.file);
    for (const b of ['stars', 'forks', 'last-commit', 'license', 'GitHub%20Pages']) assert.ok(d.text.includes(b), `${d.file} ${b}`);
    assert.deepEqual(h2(d.text), d.h2, d.file);
    assert.ok(d.text.includes(`🔗 [${PROJECT}](${PROJECT})`), d.file);
  }
  const level = (md) => headings(md).map((l) => l.match(/^#+/)[0].length);
  assert.deepEqual(level(DOCS.en.text), level(DOCS.ja.text));
  assert.ok(headings(DOCS.ja.text).length >= 17, String(headings(DOCS.ja.text).length));
});

test('画像: README から参照する画像はすべて実在し300KB以下。assets の PNG は README から参照されているものだけ', () => {
  for (const d of Object.values(DOCS)) {
    const refs = [...d.text.matchAll(/!\[[^\]]*\]\((assets\/[^)]+)\)/g)].map((m) => m[1]);
    assert.equal(refs.length, 3, d.file);
    for (const r of refs) {
      assert.match(r, d.shots, r);
      assert.ok(fs.statSync(path.join(ROOT, r)).size <= 300 * 1024, r);
    }
    const dir = d.file === 'README.md' ? 'assets' : 'assets/en';
    const pngs = fs.readdirSync(path.join(ROOT, dir)).filter((f) => f.endsWith('.png')).map((f) => `${dir}/${f}`).sort();
    assert.deepEqual(pngs, [...refs].sort(), dir);
  }
});

test('README に書いた事実（6種類・各手法・RFC 793 非準拠・ICMP type 3/code 3・ポート範囲）が載り、計算部と合う', () => {
  for (const d of Object.values(DOCS)) for (const f of d.facts) assert.ok(d.text.includes(f), `${d.file}: ${f}`);
  assert.deepEqual(C.SCAN_IDS, ['tcp-connect', 'tcp-syn', 'fin', 'null', 'xmas', 'udp']);
  assert.deepEqual(C.validatePort('65535'), { ok: true, value: 65535 });
  assert.equal(C.validatePort('65536').ok, false);
  assert.deepEqual(C.SCANS.udp.closed.frames.at(-1).icmp, { type: 3, code: 3 });
});

function files(dir = '') {
  const out = [];
  for (const e of fs.readdirSync(path.join(ROOT, dir), { withFileTypes: true })) {
    if (['.git', '.claude', 'node_modules'].includes(e.name)) continue;
    const rel = dir ? `${dir}/${e.name}` : e.name;
    if (e.isDirectory()) out.push(`${rel}/`, ...files(rel));
    else out.push(rel);
  }
  return out;
}

test('ディレクトリー構造: すべてのファイルとディレクトリーが載り、ファイル行には説明がある', () => {
  const all = files();
  for (const d of Object.values(DOCS)) {
    const tree = d.text.match(/```text\nport-scan-visualizer\/\n([\s\S]*?)```/)[1].split('\n').filter(Boolean);
    const listed = [];
    const stack = [];
    for (const line of tree) {
      const m = line.match(/^((?:│   |    )*)[├└]── (\S+?)(\/?)(?:\s+#\s+\S.*)?$/);
      assert.ok(m, `${d.file}: ${line}`);
      const depth = m[1].length / 4;
      stack.length = depth;
      stack.push(m[2] + m[3]);
      listed.push(stack.join(''));
      if (m[3] !== '/') assert.match(line, /#\s+\S/, `${d.file}: ${line}`); // ファイル行には説明を付ける
    }
    assert.deepEqual([...listed].sort(), [...all].sort(), d.file);
  }
});

test('表記: 禁止語がない。強調は1節に2カ所まで、箇条書きの先頭を太字にしない。日本語と英数字のあいだに半角空白を入れない', () => {
  for (const d of Object.values(DOCS)) {
    const body = noCode(d.text);
    assert.doesNotMatch(body, d.forbidden, d.file);
    for (const h of d.h2) {
      const n = (section(body, h).match(/\*\*/g) || []).length / 2;
      assert.ok(n <= 2, `${d.file} ${h}: ${n}`);
    }
    assert.doesNotMatch(body, /^\s*- \*\*/m, d.file);
  }
  const J = '[\\u3040-\\u30ff\\u3400-\\u9fff\\uff00-\\uffef]';
  const bad = new RegExp(`${J} [A-Za-z0-9(\`]|[A-Za-z0-9)\`] ${J}`);
  for (const line of noCode(DOCS.ja.text).split('\n')) {
    if (line.startsWith('MIT License')) continue;
    assert.doesNotMatch(line, bad, line);
  }
});
