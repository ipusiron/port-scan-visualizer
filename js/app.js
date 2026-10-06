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
  let paused = false;
  let pauseStart = 0;
  let pausedAccum = 0; // この再生で一時停止していた合計ミリ秒
  let lastValidPort = C.DEFAULT_PORT;

  // OS で「視差効果を減らす」を選んでいるときは、パケットを動かさず着地点に置く
  const reduceMotion = () => {
    try { return window.matchMedia('(prefers-reduced-motion: reduce)').matches; } catch { return false; }
  };
  // 一時停止の分を差し引いた、フレーム開始からの経過（basePaused はフレーム開始時点の pausedAccum）
  function elapsed(start, basePaused) {
    const live = pausedAccum + (paused ? performance.now() - pauseStart : 0);
    return performance.now() - start - (live - basePaused);
  }

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
  const currentCompliant = () => $('complianceToggle').checked;
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

  // RFC 準拠トグルの表示と、判定できない注記の出し分け
  function updateCompliance() {
    const compliant = currentCompliant();
    $('complianceLabel').textContent = t(compliant ? 'ctl.compliant' : 'ctl.noncompliant');
    $('complianceNote').hidden = !(!compliant && C.affectedByCompliance(currentScan()));
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
      const start = performance.now();
      const basePaused = pausedAccum;
      const motion = !reduceMotion();
      const dur = motion ? frameDuration() : Math.min(frameDuration(), 500); // 動かさないときは待ちも短く

      if (frame.dir === 'timeout') {
        // 無応答は、中央に淡く「✕」を置いて間を取る（パケットは動かさない）
        label.textContent = '✕';
        label.setAttribute('fill', 'var(--text)');
        box.setAttribute('fill', 'var(--timeout-bg)');
        g.setAttribute('transform', `translate(${SVG.cx},${SVG.cy})`);
        g.setAttribute('opacity', '0.5');
        const tick = () => {
          if (myRun !== runId) { g.setAttribute('opacity', '0'); return resolve(); }
          if (elapsed(start, basePaused) >= dur) { g.setAttribute('opacity', '0'); return resolve(); }
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
      if (!motion) g.setAttribute('transform', `translate(${to},${y})`); // 動かさないときは着地点に置く
      const tick = () => {
        if (myRun !== runId) { g.setAttribute('opacity', '0'); return resolve(); }
        const p = Math.min(1, elapsed(start, basePaused) / dur);
        if (motion) g.setAttribute('transform', `translate(${from + (to - from) * p},${y})`);
        if (p >= 1) { g.setAttribute('opacity', '0'); return resolve(); }
        requestAnimationFrame(tick);
      };
      requestAnimationFrame(tick);
    });
  }

  function gap(myRun) {
    return new Promise((resolve) => {
      const start = performance.now();
      const basePaused = pausedAccum;
      const base = reduceMotion() ? Math.min(frameDuration(), 500) : frameDuration();
      const d = base * 0.25;
      const tick = () => {
        if (myRun !== runId || elapsed(start, basePaused) >= d) return resolve();
        requestAnimationFrame(tick);
      };
      requestAnimationFrame(tick);
    });
  }

  // 再生ボタンの表示: 停止中＝再生、再生中＝一時停止、一時停止中＝再開
  function updatePlayLabel() {
    const btn = $('playBtn');
    if (!playing) { btn.textContent = t('ctl.play'); btn.setAttribute('aria-pressed', 'false'); return; }
    btn.textContent = t(paused ? 'ctl.resume' : 'ctl.pause');
    btn.setAttribute('aria-pressed', paused ? 'false' : 'true');
  }

  function stopState() {
    playing = false;
    paused = false;
    updatePlayLabel();
    $('packet-group').setAttribute('opacity', '0');
  }

  // 再生中に押されたら一時停止・再開を切り替える（止めていた時間は elapsed から差し引く）
  function togglePause() {
    if (!playing) return;
    paused = !paused;
    if (paused) pauseStart = performance.now();
    else pausedAccum += performance.now() - pauseStart;
    updatePlayLabel();
  }

  async function play() {
    if (!validatePortField(true)) { $('portInput').focus(); return; }
    const id = currentScan();
    const state = currentState();
    const compliant = currentCompliant();
    const frames = C.getFrames(id, state, compliant);
    clearTimeline();
    setBadge('pending');
    playing = true;
    paused = false;
    pausedAccum = 0;
    const myRun = ++runId;
    updatePlayLabel();
    for (let i = 0; i < frames.length; i++) {
      if (myRun !== runId) break;
      addTimeline(frames[i]);
      await animateFrame(frames[i], myRun);
      if (myRun !== runId) break;
      await gap(myRun);
    }
    if (myRun === runId) {
      setBadge(C.getJudgement(id, state, compliant));
      stopState();
    }
  }

  // リセットは停止も兼ねる（runId を進めてループを無効にし、最初の状態へ戻す）
  function reset() {
    runId++;
    playing = false;
    paused = false;
    pausedAccum = 0;
    updatePlayLabel();
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
    updateCompliance();
    renderExplain();
    renderIds();
    renderHelp();
    // 再生中でなければ、時系列と判定を今の言語で描き直す（英語に日本語を残さない）
    if (!playing) {
      reset();
    } else {
      setBadge($('judgementBadge').dataset.judge || 'pending');
      updatePlayLabel();
    }
  }

  function onScanChange() {
    updateScanMeta();
    updateCompliance();
    renderExplain();
    renderIds();
    reset();
  }

  function onStateChange() {
    updateStateLabel();
    reset();
  }

  function onComplianceChange() {
    updateCompliance();
    reset();
  }

  function init() {
    I.init();
    populateScans();
    initHelp();
    $('scanSelect').addEventListener('change', onScanChange);
    $('portStateToggle').addEventListener('change', onStateChange);
    $('complianceToggle').addEventListener('change', onComplianceChange);
    $('portInput').addEventListener('blur', () => validatePortField(true));
    $('speedControl').addEventListener('change', () => {});
    $('playBtn').addEventListener('click', () => { if (playing) togglePause(); else play(); });
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
