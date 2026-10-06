// Port Scan Visualizer の画面（DOM の処理だけ。計算は psv-core.js、文言は messages.js）
(() => {
  'use strict';

  const C = globalThis.PsvCore;
  const I = globalThis.PsvI18n;
  const Theme = globalThis.PsvTheme;
  const M = globalThis.PsvMessages;
  const t = (key, vars) => M.t(key, vars);
  const $ = (id) => document.getElementById(id);

  const SVG = { outY: 40, inY: 80, x0: 40, x1: 460, cx: 250, cy: 60 };
  const BASE_MS = 1400; // 1x のときのパケット1つの移動時間

  let runId = 0;      // 再生のたびに増やす。古い rAF はこれで無効にする
  let playing = false;
  let lastValidPort = C.DEFAULT_PORT;

  // 太字（**）・インラインコード（`）・改行（\n）を要素で組み立てる（HTML としては解釈しない）
  function rich(el, text) {
    el.replaceChildren();
    String(text).split('\n').forEach((line, li) => {
      if (li) el.append(document.createElement('br'));
      line.split('`').forEach((seg, ci) => {
        if (ci % 2) {
          const code = document.createElement('code');
          code.textContent = seg;
          el.append(code);
        } else {
          seg.split('**').forEach((part, bi) => {
            if (!part) return;
            if (bi % 2) {
              const strong = document.createElement('strong');
              strong.textContent = part;
              el.append(strong);
            } else {
              el.append(document.createTextNode(part));
            }
          });
        }
      });
    });
  }

  const currentScan = () => $('scanSelect').value;
  const currentState = () => ($('portStateToggle').checked ? 'open' : 'closed');
  const speedFactor = () => parseFloat($('speedControl').value) || 1;
  const frameDuration = () => BASE_MS / speedFactor();

  // ---- スキャンの選択肢 ----
  function populateScans() {
    const sel = $('scanSelect');
    const prev = sel.value;
    sel.replaceChildren();
    for (const id of C.SCAN_IDS) {
      const o = document.createElement('option');
      o.value = id;
      o.textContent = t(`scan.${id}.name`);
      sel.append(o);
    }
    if (C.SCAN_IDS.includes(prev)) sel.value = prev;
  }

  // 選んだ手法に合わせて、標的の proto 表記と凡例（TCP フラグ／プロトコル）を切り替える
  function updateScanMeta() {
    const proto = C.SCANS[currentScan()].proto;
    const isUdp = proto === 'UDP';
    $('protoLabel').textContent = proto.toLowerCase();
    $('tcpLegend').hidden = isUdp;
    $('protoLegend').hidden = !isUdp;
    $('legendLabel').textContent = t(isUdp ? 'node.legendProto' : 'node.legendTcp');
  }

  function updateStateLabel() {
    $('stateLabel').textContent = t($('portStateToggle').checked ? 'ctl.stateOpen' : 'ctl.stateClosed');
  }

  // ---- ポート入力（確定のときだけ検証。打っている間は書き戻さない） ----
  function validatePortField(commit) {
    const res = C.validatePort($('portInput').value);
    $('portError').hidden = res.ok;
    $('portInput').setAttribute('aria-invalid', String(!res.ok));
    if (res.ok) {
      lastValidPort = res.value;
      $('portLabel').textContent = String(res.value);
    } else if (commit) {
      // 確定時に不正なら、最後に正しかった値へ戻す（表示だけ。入力は本人に直してもらう）
      $('portLabel').textContent = String(lastValidPort);
    }
    return res.ok;
  }

  // ---- 時系列 ----
  function renderEmptyTimeline() {
    const ol = $('timelineList');
    ol.replaceChildren();
    const li = document.createElement('li');
    li.className = 'tl-empty';
    li.textContent = t('sec.timelineEmpty');
    ol.append(li);
  }

  function clearTimeline() {
    $('timelineList').replaceChildren();
  }

  function addTimeline(frame) {
    const li = document.createElement('li');
    const tag = document.createElement('span');
    tag.className = 'tl-packet';
    tag.dataset.dir = frame.dir;
    tag.textContent = frame.dir === 'timeout' ? '✕' : C.packetLabel(frame);
    const desc = document.createElement('span');
    desc.className = 'tl-desc';
    rich(desc, t(frame.descKey));
    li.append(tag, desc);
    $('timelineList').append(li);
  }

  // ---- 判定バッジ ----
  function setBadge(judge) {
    const b = $('judgementBadge');
    b.dataset.judge = judge;
    b.textContent = t(`judge.${judge}`);
  }

  // ---- パケットの色 ----
  function packetColor(frame) {
    if (frame.proto === 'ICMP') return 'var(--bad)';
    if (frame.flags && frame.flags.includes('RST')) return 'var(--bad)';
    if (frame.dir === 'in') return 'var(--good)';
    return 'var(--accent)';
  }

  // ---- 1フレームのアニメーション（runId が変わったら途中で止める） ----
  function animateFrame(frame, myRun) {
    return new Promise((resolve) => {
      const g = $('packet-group');
      const box = $('packet-box');
      const label = $('packet-flags');
      const dur = frameDuration();
      const start = performance.now();

      if (frame.dir === 'timeout') {
        // 無応答は、中央に淡く「✕」を置いて間を取る（パケットは動かさない）
        label.textContent = '✕';
        label.setAttribute('fill', 'var(--text)');
        box.setAttribute('fill', 'var(--timeout-bg)');
        g.setAttribute('transform', `translate(${SVG.cx},${SVG.cy})`);
        g.setAttribute('opacity', '0.5');
        const tick = () => {
          if (myRun !== runId) { g.setAttribute('opacity', '0'); return resolve(); }
          if (performance.now() - start >= dur) { g.setAttribute('opacity', '0'); return resolve(); }
          requestAnimationFrame(tick);
        };
        requestAnimationFrame(tick);
        return;
      }

      const out = frame.dir === 'out';
      const y = out ? SVG.outY : SVG.inY;
      const from = out ? SVG.x0 : SVG.x1;
      const to = out ? SVG.x1 : SVG.x0;
      label.textContent = C.packetLabel(frame);
      label.setAttribute('fill', '#fff');
      box.setAttribute('fill', packetColor(frame));
      g.setAttribute('opacity', '1');
      const tick = (now) => {
        if (myRun !== runId) { g.setAttribute('opacity', '0'); return resolve(); }
        const p = Math.min(1, (now - start) / dur);
        g.setAttribute('transform', `translate(${from + (to - from) * p},${y})`);
        if (p >= 1) { g.setAttribute('opacity', '0'); return resolve(); }
        requestAnimationFrame(tick);
      };
      requestAnimationFrame(tick);
    });
  }

  function gap(myRun) {
    return new Promise((resolve) => {
      const start = performance.now();
      const d = frameDuration() * 0.25;
      const tick = () => {
        if (myRun !== runId || performance.now() - start >= d) return resolve();
        requestAnimationFrame(tick);
      };
      requestAnimationFrame(tick);
    });
  }

  function stopState() {
    playing = false;
    $('playBtn').textContent = t('ctl.play');
    $('playBtn').setAttribute('aria-pressed', 'false');
    $('packet-group').setAttribute('opacity', '0');
  }

  // 停止（本人が再生中に押した）。runId を進めてループを無効にし、判定は出さない
  function stop() {
    runId++;
    stopState();
  }

  async function play() {
    if (playing) { stop(); return; }
    if (!validatePortField(true)) { $('portInput').focus(); return; }
    const id = currentScan();
    const state = currentState();
    const frames = C.getFrames(id, state);
    clearTimeline();
    setBadge('pending');
    playing = true;
    const myRun = ++runId;
    $('playBtn').textContent = t('ctl.pause');
    $('playBtn').setAttribute('aria-pressed', 'true');
    for (let i = 0; i < frames.length; i++) {
      if (myRun !== runId) break;
      addTimeline(frames[i]);
      await animateFrame(frames[i], myRun);
      if (myRun !== runId) break;
      await gap(myRun);
    }
    if (myRun === runId) {
      setBadge(C.getJudgement(id, state));
      stopState();
    }
  }

  function reset() {
    runId++;
    playing = false;
    $('playBtn').textContent = t('ctl.play');
    $('playBtn').setAttribute('aria-pressed', 'false');
    $('packet-group').setAttribute('opacity', '0');
    setBadge('pending');
    renderEmptyTimeline();
  }

  // ---- 解説・IDS ----
  function block(headingKey, type, text) {
    const wrap = document.createElement('div');
    wrap.className = 'explain-block';
    const h = document.createElement('h3');
    h.textContent = t(headingKey);
    wrap.append(h);
    if (type === 'ul') {
      const ul = document.createElement('ul');
      for (const line of String(text).split('\n')) {
        if (!line) continue;
        const li = document.createElement('li');
        rich(li, line);
        ul.append(li);
      }
      wrap.append(ul);
    } else {
      const p = document.createElement('p');
      rich(p, text);
      wrap.append(p);
    }
    return wrap;
  }

  function renderExplain() {
    const id = currentScan();
    const box = $('explainBox');
    box.replaceChildren();
    box.append(block('sec.summary', 'p', t(`scan.${id}.summary`)));
    box.append(block('sec.pros', 'ul', t(`scan.${id}.pros`)));
    box.append(block('sec.cons', 'ul', t(`scan.${id}.cons`)));
    box.append(block('sec.priv', 'p', t(`scan.${id}.priv`)));
  }

  function hasKey(key) {
    return Object.prototype.hasOwnProperty.call(M.MESSAGES.ja, key);
  }

  function renderIds() {
    const id = currentScan();
    const box = $('idsCommentary');
    box.replaceChildren();
    const det = C.DETECTABILITY[id];
    const badge = document.createElement('span');
    badge.className = 'det-badge';
    badge.dataset.level = det;
    badge.textContent = `${t('sec.detect')}：${t(`det.${det}`)}`;
    box.append(badge);
    const p = document.createElement('p');
    rich(p, t(`scan.${id}.ids`));
    box.append(p);
    if (hasKey(`scan.${id}.evasion`)) box.append(block('sec.evasion', 'p', t(`scan.${id}.evasion`)));
  }

  // ---- ヘルプのモーダル ----
  let lastFocused = null;

  function renderHelp() {
    const body = $('helpBody');
    body.replaceChildren();
    for (const item of M.HELP) {
      if (item.type === 'h') {
        const h = document.createElement('h3');
        h.textContent = t(item.key);
        body.append(h);
      } else if (item.type === 'p') {
        const p = document.createElement('p');
        rich(p, t(item.key));
        body.append(p);
      } else {
        const list = document.createElement(item.type === 'ol' ? 'ol' : 'ul');
        for (const key of item.keys) {
          const li = document.createElement('li');
          rich(li, t(key));
          list.append(li);
        }
        body.append(list);
      }
    }
  }

  function openHelp() {
    lastFocused = document.activeElement;
    $('helpModal').hidden = false;
    $('closeModal').focus();
  }

  function closeHelp() {
    $('helpModal').hidden = true;
    if (lastFocused) lastFocused.focus();
  }

  function initHelp() {
    $('btn-help').addEventListener('click', openHelp);
    $('closeModal').addEventListener('click', closeHelp);
    $('helpModal').addEventListener('click', (e) => {
      if (e.target === $('helpModal')) closeHelp();
    });
    document.addEventListener('keydown', (e) => {
      if ($('helpModal').hidden) return;
      if (e.key === 'Escape') { closeHelp(); return; }
      if (e.key !== 'Tab') return;
      const focusable = $('helpModal').querySelectorAll('button, a[href], [tabindex]:not([tabindex="-1"])');
      if (!focusable.length) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    });
  }

  // ---- 言語 ----
  function applyLanguage() {
    I.applyStaticText();
    Theme.refresh($('btn-theme'));
    populateScans();
    updateScanMeta();
    updateStateLabel();
    renderExplain();
    renderIds();
    renderHelp();
    // 再生中でなければ、時系列と判定を今の言語で描き直す（英語に日本語を残さない）
    if (!playing) {
      reset();
    } else {
      setBadge($('judgementBadge').dataset.judge || 'pending');
    }
  }

  function onScanChange() {
    updateScanMeta();
    renderExplain();
    renderIds();
    reset();
  }

  function onStateChange() {
    updateStateLabel();
    reset();
  }

  function init() {
    I.init();
    populateScans();
    initHelp();
    $('scanSelect').addEventListener('change', onScanChange);
    $('portStateToggle').addEventListener('change', onStateChange);
    $('portInput').addEventListener('blur', () => validatePortField(true));
    $('speedControl').addEventListener('change', () => {});
    $('playBtn').addEventListener('click', play);
    $('resetBtn').addEventListener('click', reset);
    $('btn-theme').addEventListener('click', () => Theme.toggle($('btn-theme')));
    $('btn-lang').addEventListener('click', () => {
      I.set(I.lang === 'ja' ? 'en' : 'ja');
      applyLanguage();
    });
    applyLanguage();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
