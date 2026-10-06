/* Port Scan Visualizer with SVG Animation
 * - 実スキャンは行わない
 * - SVGアニメーションでパケット移動を可視化
 */

const scanSelect = document.getElementById('scanSelect');
const portInput  = document.getElementById('portInput');
const playBtn    = document.getElementById('playBtn');
const resetBtn   = document.getElementById('resetBtn');
const portLabel  = document.getElementById('portLabel');
const timelineEl = document.getElementById('timelineList');
const explainBox = document.getElementById('explainBox');
const judgeBadge = document.getElementById('judgementBadge');
const packetGroup = document.getElementById('packet-group');
const speedControl = document.getElementById('speedControl');
const legendLabel = document.getElementById('legendLabel');
const tcpLegend = document.getElementById('tcpLegend');
const udpLegend = document.getElementById('udpLegend');
const portStateToggle = document.getElementById('portStateToggle');
const stateLabel = document.getElementById('stateLabel');
const idsCommentary = document.getElementById('idsCommentary');
const themeToggle = document.getElementById('themeToggle');
const themeIcon = themeToggle.querySelector('.theme-icon');

// Animation state
const animationState = {
  isPlaying: false,
  currentFrame: 0,
  animationQueue: [],
  abortController: null,
  speed: 1,
  portState: 'open' // 'open' or 'closed'
};

// Security: HTML sanitization function
function sanitizeHTML(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

// Security: Validate port number input
function validatePort(port) {
  const portNum = parseInt(port, 10);
  if (isNaN(portNum) || portNum < 1 || portNum > 65535) {
    return 80; // Default safe port
  }
  return portNum;
}

// Theme management
function initializeTheme() {
  const savedTheme = localStorage.getItem('theme') || 'dark';
  setTheme(savedTheme);
}

function setTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  localStorage.setItem('theme', theme);
  
  // Update button icon and aria-label - show current mode icon
  if (theme === 'light') {
    themeIcon.textContent = '🌙'; // Show moon for light mode (to switch to dark)
    themeToggle.setAttribute('aria-label', 'ダークモードに切り替え');
  } else {
    themeIcon.textContent = '☀️'; // Show sun for dark mode (to switch to light)
    themeToggle.setAttribute('aria-label', 'ライトモードに切り替え');
  }
}

function toggleTheme() {
  const currentTheme = document.documentElement.getAttribute('data-theme');
  const newTheme = currentTheme === 'light' ? 'dark' : 'light';
  setTheme(newTheme);
}

const SCANS = {
  "tcp-connect": {
    name: "TCP Connect（標準）",
    proto: "TCP",
    scenarios: {
      open: {
        frames: [
          {dir:"out", proto:"TCP", flags:["SYN"], desc:"SYN を送信"},
          {dir:"in",  proto:"TCP", flags:["SYN","ACK"], desc:"SYN/ACK を受信"},
          {dir:"out", proto:"TCP", flags:["ACK"], desc:"ACK を返して3ウェイ完了"},
          {dir:"out", proto:"TCP", flags:["FIN","ACK"], desc:"接続を切断"}
        ],
        judgement: "Open"
      },
      closed: {
        frames: [
          {dir:"out", proto:"TCP", flags:["SYN"], desc:"SYN を送信"},
          {dir:"in",  proto:"TCP", flags:["RST","ACK"], desc:"RST/ACK を受信（拒否）"}
        ],
        judgement: "Closed"
      }
    },
    summary: {
      pros: ["完全な接続確立で確実", "全OS対応"],
      cons: ["ログに記録される", "時間がかかる"]
    },
    ids: {
      detectability: "高",
      signatures: [
        "完全な3ウェイハンドシェイクでログに記録される",
        "アプリケーションレベルでの接続として検知される"
      ],
      evasion: [],
      comments: "最も検知されやすいスキャン方式。ほぼすべてのIDSで検知される。"
    }
  },
  "tcp-syn": {
    name: "TCP SYN（半開）",
    proto: "TCP",
    scenarios: {
      open: {
        frames: [
          {dir:"out", proto:"TCP", flags:["SYN"], desc:"SYN を送信"},
          {dir:"in",  proto:"TCP", flags:["SYN","ACK"], desc:"SYN/ACK を受信"},
          {dir:"out", proto:"TCP", flags:["RST"], desc:"RST で中断（3way未完了）"}
        ],
        judgement: "Open"
      },
      closed: {
        frames: [
          {dir:"out", proto:"TCP", flags:["SYN"], desc:"SYN を送信"},
          {dir:"in",  proto:"TCP", flags:["RST","ACK"], desc:"RST/ACK を受信（拒否）"}
        ],
        judgement: "Closed"
      }
    },
    summary: {
      pros: ["高速スキャン", "完全な接続を作らない"],
      cons: ["root権限必要", "一部のIDSで検知"]
    },
    ids: {
      detectability: "中",
      signatures: [
        "SYN→SYN/ACK→RSTパターンで検知",
        "半開き接続として記録される場合がある"
      ],
      evasion: [
        "送信間隔を調整して検知回避",
        "デコイIPアドレスの使用"
      ],
      comments: "多くのIDSで検知可能だが、TCP Connectより隠蔽性が高い。"
    }
  },
  "fin": {
    name: "FIN",
    proto: "TCP",
    scenarios: {
      open: {
        frames: [
          {dir:"out", proto:"TCP", flags:["FIN"], desc:"FIN を送信"},
          {dir:"timeout", proto:"TCP", desc:"無応答（RFC準拠）"}
        ],
        judgement: "Open/Filtered"
      },
      closed: {
        frames: [
          {dir:"out", proto:"TCP", flags:["FIN"], desc:"FIN を送信"},
          {dir:"in",  proto:"TCP", flags:["RST","ACK"], desc:"RST/ACK を受信"}
        ],
        judgement: "Closed"
      }
    },
    summary: {
      pros: ["SYNフラグなしでステルス", "単純な実装"],
      cons: ["Unix系のみ有効", "Windows無効"]
    },
    ids: {
      detectability: "低",
      signatures: [
        "FINフラグのみのパケットとして検知",
        "RFC違反のパケットパターン"
      ],
      evasion: [
        "古いIDSでは見逃される可能性",
        "パケット断片化との組み合わせ"
      ],
      comments: "ステルス性が高く、古いIDSでは検知困難。最新のIDSでは検知される。"
    }
  },
  "null": {
    name: "NULL",
    proto: "TCP",
    scenarios: {
      open: {
        frames: [
          {dir:"out", proto:"TCP", flags:[], desc:"フラグなし（NULL）を送信"},
          {dir:"timeout", proto:"TCP", desc:"無応答（RFC準拠）"}
        ],
        judgement: "Open/Filtered"
      },
      closed: {
        frames: [
          {dir:"out", proto:"TCP", flags:[], desc:"フラグなし（NULL）を送信"},
          {dir:"in",  proto:"TCP", flags:["RST","ACK"], desc:"RST/ACK を受信"}
        ],
        judgement: "Closed"
      }
    },
    summary: {
      pros: ["異常パケットでFW回避", "実装が単純"],
      cons: ["Unix系のみ有効", "Windows無効"]
    },
    ids: {
      detectability: "低",
      signatures: [
        "全フラグが0のTCPパケット",
        "RFC違反の明確な異常パケット"
      ],
      evasion: [
        "多くのファイアウォールを通過",
        "古いネットワーク機器で見逃される"
      ],
      comments: "非常にステルスだが、最新のIDSでは異常パケットとして検知される。"
    }
  },
  "xmas": {
    name: "Xmas（FIN+PSH+URG）",
    proto: "TCP",
    scenarios: {
      open: {
        frames: [
          {dir:"out", proto:"TCP", flags:["FIN","PSH","URG"], desc:"Xmas フラグを送信"},
          {dir:"timeout", proto:"TCP", desc:"無応答（RFC準拠）"}
        ],
        judgement: "Open/Filtered"
      },
      closed: {
        frames: [
          {dir:"out", proto:"TCP", flags:["FIN","PSH","URG"], desc:"Xmas フラグを送信"},
          {dir:"in",  proto:"TCP", flags:["RST","ACK"], desc:"RST/ACK を受信"}
        ],
        judgement: "Closed"
      }
    },
    summary: {
      pros: ["古いUnix系で有効", "FW回避の可能性"],
      cons: ["異常フラグで目立つ", "Windows無効"]
    },
    ids: {
      detectability: "中",
      signatures: [
        "FIN+PSH+URGフラグの組み合わせ",
        "Xmasツリーパターンとして有名"
      ],
      evasion: [
        "一部のファイアウォールを回避",
        "古いUnixシステムで有効"
      ],
      comments: "特徴的なフラグパターンで多くのIDSで検知される。有名な手法のため対策済み。"
    }
  },
  "udp": {
    name: "UDP",
    proto: "UDP",
    scenarios: {
      open: {
        frames: [
          {dir:"out", proto:"UDP", desc:"UDPデータグラムを送信"},
          {dir:"timeout", proto:"UDP", desc:"無応答（多くの場合）"}
        ],
        judgement: "Open/Filtered"
      },
      closed: {
        frames: [
          {dir:"out", proto:"UDP", desc:"UDPデータグラムを送信"},
          {dir:"in",  proto:"ICMP", icmpType:"Port Unreachable", desc:"ICMP Port Unreachable"}
        ],
        judgement: "Closed"
      }
    },
    summary: {
      pros: ["UDPサービス検出", "DNSやSNMP発見"],
      cons: ["非常に遅い", "ICMP制限で不正確", "多くのサービスが無応答"]
    },
    ids: {
      detectability: "低",
      signatures: [
        "UDP宛先不到達ICMPメッセージ",
        "UDPフラッド攻撃として検知される場合"
      ],
      evasion: [
        "送信レート制限で検知回避",
        "ICMPレスポンス制限の利用"
      ],
      comments: "検知は困難だが、大量送信時はDDoS攻撃として検知される可能性。"
    }
  }
};

// --- Flag colors ---
const flagColors = {
  SYN: '#5aa9ff',
  ACK: '#65e892', 
  FIN: '#ff7a7a',
  PSH: '#b085ff',
  URG: '#ffb86b',
  RST: '#ff6b6b'
};

// --- Animation helpers ---
function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function highlightFlags(flags, proto) {
  // Clear all active states
  document.querySelectorAll('.flag').forEach(f => f.classList.remove('active'));
  
  if (proto === "UDP" || proto === "ICMP") {
    // Show UDP legend for UDP/ICMP protocols
    tcpLegend.style.display = 'none';
    udpLegend.style.display = 'flex';
    legendLabel.textContent = 'プロトコル凡例:';
    
    if (proto === "UDP") {
      const udpFlag = udpLegend.querySelector('.flag.udp');
      if (udpFlag) udpFlag.classList.add('active');
    } else if (proto === "ICMP") {
      const icmpFlag = udpLegend.querySelector('.flag.icmp');
      if (icmpFlag) icmpFlag.classList.add('active');
    }
  } else {
    // Show TCP legend for TCP protocols
    tcpLegend.style.display = 'flex';
    udpLegend.style.display = 'none';
    legendLabel.textContent = 'TCPフラグ凡例:';
    
    if (flags && flags.length > 0) {
      flags.forEach(flag => {
        const flagEl = tcpLegend.querySelector(`[data-flag="${flag}"]`);
        if (flagEl) flagEl.classList.add('active');
      });
    } else {
      // NULL scan - highlight absence
      tcpLegend.querySelectorAll('.flag').forEach(f => {
        f.style.opacity = '0.3';
      });
      setTimeout(() => {
        tcpLegend.querySelectorAll('.flag').forEach(f => {
          f.style.opacity = '';
        });
      }, 800);
    }
  }
}

function clearFlagHighlights() {
  document.querySelectorAll('.flag').forEach(f => {
    f.classList.remove('active');
    f.style.opacity = '';
  });
}

function getCurrentFrames(scanType) {
  const scan = SCANS[scanType];
  const scenario = scan.scenarios[animationState.portState];
  return scenario.frames;
}

function getCurrentJudgement(scanType) {
  const scan = SCANS[scanType];
  const scenario = scan.scenarios[animationState.portState];
  return scenario.judgement;
}

function updatePortStateUI() {
  if (animationState.portState === 'open') {
    stateLabel.textContent = 'Open';
    stateLabel.style.color = 'var(--good)';
  } else {
    stateLabel.textContent = 'Closed';
    stateLabel.style.color = 'var(--bad)';
  }
}

function getPacketColor(frame) {
  // Handle timeout and non-TCP protocols
  if (frame.dir === "timeout") return "var(--muted)";
  if (frame.proto === "ICMP") return "var(--warn)";
  if (frame.proto === "UDP") return "var(--accent)";
  
  // Handle TCP packets with flags
  if (frame.flags && frame.flags.length > 0) {
    // If mixed flags (multiple flags), use direction-based colors for distinction
    if (frame.flags.length > 1) {
      if (frame.flags.includes("RST")) return flagColors.RST;
      return frame.dir === "out" ? "var(--accent)" : "var(--good)";
    }
    // Single flag - use flag color from legend
    const singleFlag = frame.flags[0];
    if (flagColors[singleFlag]) {
      return flagColors[singleFlag];
    }
  }
  
  // Default colors for direction
  if (frame.dir === "out") return "var(--accent)";
  if (frame.dir === "in") return "var(--good)";
  
  return "var(--accent)";
}

async function animatePacket(frame, index) {
  const packet = packetGroup;
  const rect = packet.querySelector('.packet-box');
  const text = packet.querySelector('.packet-flags');
  const speed = animationState.speed;
  
  // Set packet content
  const flags = frame.flags ? frame.flags.join("+") : 
                (frame.proto === "UDP" ? "UDP" : 
                 frame.proto === "ICMP" ? "ICMP" : "NULL");
  text.textContent = flags;
  
  // Set packet color
  const color = getPacketColor(frame);
  rect.setAttribute('fill', color);
  
  // Highlight flags in legend
  highlightFlags(frame.flags, frame.proto);
  
  // Highlight timeline item
  const timelineItems = timelineEl.querySelectorAll('li');
  timelineItems.forEach(item => item.classList.remove('active'));
  if (timelineItems[index]) {
    timelineItems[index].classList.add('active');
  }
  
  // Calculate adjusted durations
  const moveDuration = 800 / speed;
  const fadeOutDuration = 1000 / speed;
  const hideDuration = 200 / speed;
  
  // Determine path and animation
  if (frame.dir === "out") {
    // Scanner to Target
    packet.style.opacity = 1;
    packet.style.transform = 'translate(50px, 50px)';
    await delay(50 / speed);
    packet.style.transition = `transform ${moveDuration}ms ease-in-out`;
    packet.style.transform = 'translate(450px, 50px)';
    await delay(moveDuration);
  } else if (frame.dir === "in") {
    // Target to Scanner
    packet.style.opacity = 1;
    packet.style.transform = 'translate(450px, 50px)';
    await delay(50 / speed);
    packet.style.transition = `transform ${moveDuration}ms ease-in-out`;
    packet.style.transform = 'translate(50px, 50px)';
    await delay(moveDuration);
  } else if (frame.dir === "timeout") {
    // Show timeout effect
    packet.style.opacity = 0.5;
    packet.style.transform = 'translate(250px, 50px)';
    rect.setAttribute('stroke-dasharray', '5,5');
    await delay(50 / speed);
    packet.style.transition = `opacity ${fadeOutDuration}ms ease-out`;
    packet.style.opacity = 0;
    await delay(fadeOutDuration);
    rect.removeAttribute('stroke-dasharray');
  }
  
  // Hide packet
  packet.style.transition = `opacity ${hideDuration}ms`;
  packet.style.opacity = 0;
  await delay(hideDuration);
}

async function animateSequence(frames, judgement) {
  animationState.isPlaying = true;
  animationState.currentFrame = 0;
  playBtn.textContent = "⏸ 停止";
  playBtn.disabled = false;
  speedControl.disabled = true; // Disable speed control during playback
  portStateToggle.disabled = true; // Disable port state toggle during playback
  
  for (let i = 0; i < frames.length; i++) {
    if (!animationState.isPlaying) break;
    
    animationState.currentFrame = i;
    await animatePacket(frames[i], i);
    
    await delay(200 / animationState.speed); // Delay between packets
  }
  
  // Set final judgement
  if (judgement === "Open") setJudgeBadge("open");
  else if (judgement === "Closed") setJudgeBadge("closed");
  else if (judgement.includes("Open") || judgement.includes("Filtered")) setJudgeBadge("open_or_filtered");
  
  animationState.isPlaying = false;
  playBtn.textContent = "▶ 再生";
  speedControl.disabled = false; // Re-enable speed control
  portStateToggle.disabled = false; // Re-enable port state toggle
}

function stopAnimation() {
  animationState.isPlaying = false;
  playBtn.textContent = "▶ 再生";
  speedControl.disabled = false; // Re-enable speed control
  portStateToggle.disabled = false; // Re-enable port state toggle
  const timelineItems = timelineEl.querySelectorAll('li');
  timelineItems.forEach(item => item.classList.remove('active'));
  packetGroup.style.opacity = 0;
  clearFlagHighlights();
}

// --- Helpers ---
function renderTimeline(frames){
  timelineEl.innerHTML = "";
  frames.forEach(f=>{
    const li = document.createElement('li');
    const flags = f.flags ? f.flags.join("+") : (f.proto==="UDP" ? "—" : "NULL");
    const dir = f.dir==="out" ? "→" : (f.dir==="in" ? "←" : "…");
    li.textContent = `[${f.proto}] ${dir} ${flags} : ${f.desc || ""}`;
    timelineEl.appendChild(li);
  });
}

function renderExplain(scan){
  const { pros=[], cons=[] } = scan.summary || {};
  explainBox.innerHTML = `
    <div><strong>${sanitizeHTML(scan.name)}</strong></div>
    <div class="hint">※これは学習用の疑似挙動です。実環境ではOS/ミドルウェア差があります。</div>
    <div style="margin-top:.6rem;display:grid;grid-template-columns:1fr 1fr;gap:.75rem">
      <div>
        <div><b>利点</b></div>
        <ul>${pros.map(x=>`<li>${sanitizeHTML(x)}</li>`).join("")}</ul>
      </div>
      <div>
        <div><b>欠点</b></div>
        <ul>${cons.map(x=>`<li>${sanitizeHTML(x)}</li>`).join("")}</ul>
      </div>
    </div>
  `;
}

function renderIDSCommentary(scan){
  const ids = scan.ids || {};
  const detectabilityClass = {
    "高": "high-detect",
    "中": "medium-detect", 
    "低": "low-detect"
  };
  
  const detectability = sanitizeHTML(ids.detectability || '不明');
  const cssClass = detectabilityClass[ids.detectability] || '';
  
  idsCommentary.innerHTML = `
    <div class="ids-header">
      <span class="detectability-badge ${cssClass}">${detectability}検知性</span>
    </div>
    <div class="ids-content">
      <div class="ids-section">
        <h4>🔍 検知シグネチャ</h4>
        <ul class="ids-list">
          ${(ids.signatures || []).map(sig => `<li>${sanitizeHTML(sig)}</li>`).join('')}
        </ul>
      </div>
      ${(ids.evasion && ids.evasion.length > 0) ? `
        <div class="ids-section">
          <h4>🕵️ 回避技術</h4>
          <ul class="ids-list">
            ${ids.evasion.map(ev => `<li>${sanitizeHTML(ev)}</li>`).join('')}
          </ul>
        </div>
      ` : ''}
      <div class="ids-comment">
        <strong>専門家コメント:</strong> ${sanitizeHTML(ids.comments || 'コメントなし')}
      </div>
    </div>
  `;
}

function setJudgeBadge(kind){
  judgeBadge.className = "judge-badge";
  let text = "–";
  if(kind==="open"){ judgeBadge.classList.add("judge-open"); text = "Open"; }
  else if(kind==="closed"){ judgeBadge.classList.add("judge-closed"); text = "Closed"; }
  else if(kind==="open_or_filtered"){ judgeBadge.classList.add("judge-filtered"); text = "Open / Filtered / Unknown"; }
  judgeBadge.textContent = text;
}

// --- Events ---
function refresh(){
  stopAnimation();
  const validatedPort = validatePort(portInput.value || "80");
  portInput.value = validatedPort; // Update input with validated value
  portLabel.textContent = validatedPort;
  const scan = SCANS[scanSelect.value];
  const frames = getCurrentFrames(scanSelect.value);
  
  // Switch legend based on scan type
  if (scan.proto === "UDP") {
    tcpLegend.style.display = 'none';
    udpLegend.style.display = 'flex';
    legendLabel.textContent = 'プロトコル凡例:';
  } else {
    tcpLegend.style.display = 'flex';
    udpLegend.style.display = 'none';
    legendLabel.textContent = 'TCPフラグ凡例:';
  }
  
  updatePortStateUI();
  renderTimeline(frames);
  renderExplain(scan);
  renderIDSCommentary(scan);
  setJudgeBadge(null);
}

scanSelect.addEventListener('change', refresh);
portInput.addEventListener('input', refresh);

speedControl.addEventListener('change', ()=> {
  animationState.speed = parseFloat(speedControl.value);
});

portStateToggle.addEventListener('change', ()=> {
  animationState.portState = portStateToggle.checked ? 'open' : 'closed';
  refresh();
});

themeToggle.addEventListener('click', toggleTheme);

playBtn.addEventListener('click', async ()=> {
  if (animationState.isPlaying) {
    stopAnimation();
  } else {
    animationState.speed = parseFloat(speedControl.value);
    const scanType = scanSelect.value;
    const frames = getCurrentFrames(scanType);
    const judgement = getCurrentJudgement(scanType);
    await animateSequence(frames, judgement);
  }
});

resetBtn.addEventListener('click', ()=> {
  stopAnimation();
  portInput.value = 80;
  scanSelect.value = "tcp-connect";
  speedControl.value = "1";
  portStateToggle.checked = true;
  animationState.speed = 1;
  animationState.portState = 'open';
  refresh();
});

// 初期表示
initializeTheme();
refresh();
