import test from 'node:test';
import assert from 'node:assert/strict';
import { read } from './load.js';

const css = read('style.css');
function block(selector) {
  const start = css.indexOf(`${selector} {`);
  assert.ok(start >= 0, selector);
  return css.slice(start, css.indexOf('}', start));
}
const tokens = (selector) => Object.fromEntries([...block(selector).matchAll(/--([a-z0-9-]+):\s*(#[0-9a-f]{6})/g)].map((m) => [m[1], m[2]]));
const luminance = (hex) => {
  const [r, g, b] = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255)
    .map((c) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4));
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
};
const ratio = (a, b) => {
  const [x, y] = [luminance(a), luminance(b)].sort((p, q) => q - p);
  return (x + 0.05) / (y + 0.05);
};

// 文字と背景（4.5:1 以上）
const TEXT = [
  ['text', 'bg'], ['text', 'panel'], ['text', 'card'], ['muted', 'bg'], ['muted', 'panel'], ['muted', 'card'],
  ['on-accent', 'accent'], ['code-text', 'code-bg'], ['bad', 'panel'], ['accent', 'bg'], ['accent', 'panel'],
  ['det-high-text', 'det-high-bg'], ['det-medium-text', 'det-medium-bg'], ['det-low-text', 'det-low-bg']
];
// 枠や図形（3:1 以上）
const GRAPHICS = [
  ['field-border', 'panel'], ['field-border', 'card'], ['field-border', 'bg'], ['accent', 'card'], ['good', 'panel'], ['good', 'card']
];

test('ライトとダークの配色は、文字と背景が4.5:1以上、枠と図形の色が3:1以上', () => {
  for (const [name, set] of [['light', tokens(':root')], ['dark', tokens(':root[data-theme="dark"]')]]) {
    for (const [fg, bg] of TEXT) assert.ok(ratio(set[fg], set[bg]) >= 4.5, `${name} ${fg} on ${bg}: ${ratio(set[fg], set[bg]).toFixed(2)}`);
    for (const [fg, bg] of GRAPHICS) assert.ok(ratio(set[fg], set[bg]) >= 3, `${name} ${fg} on ${bg}: ${ratio(set[fg], set[bg]).toFixed(2)}`);
  }
});

test('OS の設定によるダークと、手動のダークは同じ値。ライトとダークは同じトークンを持つ', () => {
  const read2 = (sel) => Object.fromEntries([...block(sel).matchAll(/--([a-z0-9-]+):\s*([^;]+);/g)].map((m) => [m[1], m[2].trim()]));
  const os = read2(':root:not([data-theme="light"])');
  assert.equal(Object.keys(os).length, 22);
  assert.deepEqual(os, read2(':root[data-theme="dark"]'));
  assert.deepEqual(Object.keys(read2(':root')).sort(), Object.keys(os).sort());
});

test('style.css が使う色のトークンは、すべて定義されている。白の直書きをしない（SVG と凡例を除く）', () => {
  const defined = new Set(Object.keys(tokens(':root')).concat(['shadow']));
  for (const k of new Set([...css.matchAll(/var\(--([a-z0-9-]+)/g)].map((m) => m[1]))) assert.ok(defined.has(k), k);
});

test('入力欄は16px（iPhone の自動拡大を防ぐ）', () => {
  assert.match(block('select, input[type="number"]'), /font-size: 16px/);
});
