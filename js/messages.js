// 画面の文言（日本語・英語で同じキー）。t(key, vars, lang) で {name} を置き換える。globalThis.PsvMessages に置く
// 文中の **…** は太字、改行（\n）は改行として i18n.js が要素で組み立てる（HTML として解釈しない）
(() => {
  'use strict';

  const ja = {
    'ui.subtitle': '6種類のポートスキャンを、**パケットのフラグ**と**判定**をそろえて見比べる学習用ツールです',
    'ui.help': '❓ ヘルプ',
    'ui.helpLabel': 'ヘルプを開く',
    'ui.langButton': 'English',
    'ui.langLabel': 'Switch to English',
    'ui.noscript': 'このページはJavaScriptで動きます。JavaScriptを有効にしてから開き直してください。',
    'ui.repo': 'GitHubリポジトリー（ipusiron/port-scan-visualizer）',
    'ui.warning': 'このツールはブラウザーの中だけで動く学習用のシミュレーションです。実際のスキャンはしません。許可のないポートスキャンは法律や規約で禁じられている場合があります。',
    'theme.toLight': 'ライトモードに切り替える',
    'theme.toDark': 'ダークモードに切り替える',

    'ctl.title': 'スキャンの設定',
    'ctl.scan': 'スキャン手法',
    'ctl.port': 'ポート番号',
    'ctl.portHint': '標的のポート番号。1〜65535',
    'ctl.portError': 'ポート番号は1〜65535の整数にしてください。',
    'ctl.speed': 'アニメーションの速度',
    'ctl.state': '標的のポートの状態',
    'ctl.stateOpen': '開いている',
    'ctl.stateClosed': '閉じている',
    'ctl.play': '▶ 再生',
    'ctl.pause': '⏸ 停止',
    'ctl.reset': '⟲ リセット',

    'node.scanner': 'スキャナー',
    'node.target': '標的',
    'node.legendTcp': 'TCPフラグ',
    'node.legendProto': 'プロトコル',

    'judge.open': '開いている（Open）',
    'judge.closed': '閉じている（Closed）',
    'judge.openFiltered': '開/フィルター（Open｜Filtered）',
    'judge.pending': '判定前',

    'sec.timeline': '時系列',
    'sec.timelineEmpty': '「再生」を押すと、パケットの往来が1手順ずつ表示されます。',
    'sec.explain': '解説',
    'sec.ids': 'IDSでの検知',
    'sec.summary': '概要',
    'sec.pros': '利点',
    'sec.cons': '欠点',
    'sec.priv': '必要な権限',
    'sec.detect': '検知されやすさ',
    'sec.evasion': '回避の工夫',

    'det.high': '高い',
    'det.medium': '中',
    'det.low': '低い',

    // パケット1つの説明（時系列と解説で使う）
    'f.synOut': 'SYNを送り、接続を開こうとする',
    'f.synackIn': 'SYN/ACKが返る → ポートは開いている',
    'f.ackComplete': 'ACKを返し、3ウェイハンドシェイクを完了する',
    'f.finAckClose': 'FIN/ACKを送って接続を正しく閉じる',
    'f.rstAckReject': 'RST/ACKが返る → ポートは閉じている（接続を拒否）',
    'f.rstInterrupt': 'RSTを送って接続を途中で打ち切る（ハンドシェイクを完了しない）',
    'f.finOut': 'FINだけを立てて送る',
    'f.nullOut': 'フラグを1つも立てずに送る',
    'f.xmasOut': 'FIN+PSH+URGを同時に立てて送る',
    'f.udpOut': 'UDPデータグラムを送る',
    'f.icmpUnreach': 'ICMP Port Unreachable（type 3, code 3）が返る → ポートは閉じている',
    'f.timeoutRfc': '無応答（タイムアウト）→ RFC 793準拠なら開いている。フィルターでも無応答なのでopen｜filtered',
    'f.timeoutUdp': '無応答（タイムアウト）→ 開いているかフィルターされている（open｜filtered）',
    'f.rstAckIn': 'RST/ACKが返る → ポートは閉じている',

    // 手法ごと（name は手法名、summary は概要、pros・cons は \n 区切りの箇条書き）
    'scan.tcp-connect.name': 'TCP Connect（フルコネクト）',
    'scan.tcp-connect.summary': 'OSの`connect()`を使って完全な3ウェイハンドシェイクを行う、最も基本的なスキャンです。',
    'scan.tcp-connect.pros': '特権（root・管理者）が要らない\nどのOS・言語でも実装しやすい\n開閉の判定が確実',
    'scan.tcp-connect.cons': '接続を最後まで張るので相手のログに最も残りやすい\nほかのTCPスキャンより遅い',
    'scan.tcp-connect.priv': '特権は不要（`connect()`を呼ぶだけ。nmapでは`-sT`）',
    'scan.tcp-connect.ids': '接続を確立してからすぐ閉じるため、サーバーの接続ログに記録されやすく、最も気づかれやすい手法です。',

    'scan.tcp-syn.name': 'TCP SYN（ハーフオープン）',
    'scan.tcp-syn.summary': 'SYNを送り、SYN/ACKが返れば開いていると判断して、RSTで接続を打ち切ります。3ウェイハンドシェイクを完了しません。',
    'scan.tcp-syn.pros': '接続を完了しないので接続ログに残りにくい\nTCP Connectより速い\n開閉を確実に判定できる',
    'scan.tcp-syn.cons': 'rawパケットを組み立てるため特権が要る',
    'scan.tcp-syn.priv': '特権が必要（rawソケット。nmapでは`-sS`）',
    'scan.tcp-syn.ids': '歴史的に「ハーフオープン」「ステルス」と呼ばれますが、現代のIDS/IPSでは半開の接続も検知されます（ステルスは歴史的な呼称です）。',
    'scan.tcp-syn.evasion': 'デコイ（`-D`）・送信レートの調整（`-T`）・パケットの断片化（`-f`）などと組み合わせて検知を避けようとすることがあります。',

    'scan.fin.name': 'FIN',
    'scan.fin.summary': 'FINだけを立てたパケットを送ります。RFC 793準拠のスタックは、開いていれば無応答・閉じていればRST/ACKを返します。',
    'scan.fin.pros': 'SYNを送らないので、SYNだけを見る古いIDSや単純なフィルターを抜けることがある',
    'scan.fin.cons': 'RFC 793に準拠しないスタック（Windows・一部Cisco・BSDI・OS/400など）は、開閉に関係なくRSTを返すため判定できない\n無応答のとき開いているのかフィルターされているのか区別できない（open｜filtered）',
    'scan.fin.priv': '特権が必要（nmapでは`-sF`）',
    'scan.fin.ids': '古いIDSでは見逃されることがありますが、最新のIDSはこの種の変則パケットを検知します。',

    'scan.null.name': 'NULL',
    'scan.null.summary': 'フラグを1つも立てないパケットを送ります。判定のしかたはFINと同じです（開＝無応答、閉＝RST/ACK）。',
    'scan.null.pros': 'フラグがないため、特定のフラグを見るフィルターを抜けることがある',
    'scan.null.cons': 'RFC 793に準拠しないスタックでは判定できない（FINと同じ）\n無応答のときopen｜filteredの区別がつかない',
    'scan.null.priv': '特権が必要（nmapでは`-sN`）',
    'scan.null.ids': 'フラグのないパケットは正常な通信では珍しく、最新のIDSのシグネチャーに引っかかりやすいです。',

    'scan.xmas.name': 'Xmas（FIN+PSH+URG）',
    'scan.xmas.summary': 'FIN・PSH・URGを同時に立てて送ります（パケットが「点灯」して見えることからクリスマスツリーと呼ばれます）。判定はFINと同じです。',
    'scan.xmas.pros': '特定のフラグの組み合わせを想定しないフィルターを抜けることがある',
    'scan.xmas.cons': 'RFC 793に準拠しないスタックでは判定できない（FINと同じ）\nフラグの異常な組み合わせはIDSに検知されやすい',
    'scan.xmas.priv': '特権が必要（nmapでは`-sX`）',
    'scan.xmas.ids': '通常は同時に立たないフラグの組み合わせなので、IDSのシグネチャーに引っかかりやすいです。',

    'scan.udp.name': 'UDP',
    'scan.udp.summary': 'UDPデータグラムを送ります。閉じていればICMP Port Unreachable（type 3, code 3）が返り、開いていれば多くは無応答でopen｜filteredと判断します。',
    'scan.udp.pros': 'TCPでは見えないUDPサービス（DNS・SNMP・NTPなど）を調べられる',
    'scan.udp.cons': '無応答が多く判定が不確実になりやすい\nICMPのレート制限がかかると非常に遅くなる',
    'scan.udp.priv': '特権が必要（ICMPを受け取るため。nmapでは`-sU`）',
    'scan.udp.ids': 'ICMPの大量発生や、普段使われないポートへのUDPで検知されることがあります。',

    // ヘルプの文言
    'help.title': 'このツールについて',
    'help.about.h': 'このツールでできること',
    'help.about.p': '6種類のポートスキャン手法を、同じ画面でパケットの往来と判定を見比べて学べます。実際のスキャンはせず、すべてブラウザーの中のシミュレーションです。',
    'help.use.h': '使い方',
    'help.use.1': 'スキャン手法を選びます。',
    'help.use.2': '標的のポートの状態（開いている／閉じている）を切り替えます。',
    'help.use.3': '「再生」を押すと、パケットの往来が1手順ずつアニメーションで流れます。',
    'help.use.4': '時系列・解説・IDSでの検知で、なぜその判定になるかを確認します。',
    'help.judge.h': '判定の見方',
    'help.judge.1': '**Open**：開いている（応答から確実に判断できる）',
    'help.judge.2': '**Closed**：閉じている（RST/ACKまたはICMP Port Unreachableが返る）',
    'help.judge.3': '**Open｜Filtered**：無応答のため、開いているのかフィルターされているのか区別できない',
    'help.note.h': '注意点',
    'help.note.p': 'FIN・NULL・XmasはRFC 793に準拠したスタックでのみ機能します。Windows・一部のCisco・BSDI・OS/400などは開閉に関係なくRSTを返すため、これらの手法では判定できません。許可のないポートスキャンは、法律や規約で禁じられている場合があります。',
    'help.sources.h': '参考',
    'help.sources.1': 'nmap公式ドキュメント（Port Scanning Techniques）',
    'help.sources.2': 'RFC 9293（TCP）, RFC 792（ICMP）'
  };

  const en = {
    'ui.subtitle': 'A learning tool to compare six port-scan methods side by side, with the same **packet flags** and **verdicts**',
    'ui.help': '❓ Help',
    'ui.helpLabel': 'Open help',
    'ui.langButton': '日本語',
    'ui.langLabel': '日本語に切り替える',
    'ui.noscript': 'This page runs on JavaScript. Please enable JavaScript and reopen it.',
    'ui.repo': 'GitHub repository (ipusiron/port-scan-visualizer)',
    'ui.warning': 'This tool is an educational simulation that runs entirely in your browser. It performs no real scanning. Scanning ports without permission may be prohibited by law or by terms of service.',
    'theme.toLight': 'Switch to light mode',
    'theme.toDark': 'Switch to dark mode',

    'ctl.title': 'Scan settings',
    'ctl.scan': 'Scan method',
    'ctl.port': 'Port number',
    'ctl.portHint': 'Target port number. 1-65535',
    'ctl.portError': 'The port number must be an integer from 1 to 65535.',
    'ctl.speed': 'Animation speed',
    'ctl.state': 'Target port state',
    'ctl.stateOpen': 'Open',
    'ctl.stateClosed': 'Closed',
    'ctl.play': '▶ Play',
    'ctl.pause': '⏸ Stop',
    'ctl.reset': '⟲ Reset',

    'node.scanner': 'Scanner',
    'node.target': 'Target',
    'node.legendTcp': 'TCP flags',
    'node.legendProto': 'Protocol',

    'judge.open': 'Open',
    'judge.closed': 'Closed',
    'judge.openFiltered': 'Open | Filtered',
    'judge.pending': 'Not judged yet',

    'sec.timeline': 'Timeline',
    'sec.timelineEmpty': 'Press "Play" to show the packet exchange step by step.',
    'sec.explain': 'Explanation',
    'sec.ids': 'IDS detection',
    'sec.summary': 'Overview',
    'sec.pros': 'Strengths',
    'sec.cons': 'Weaknesses',
    'sec.priv': 'Privilege required',
    'sec.detect': 'Detectability',
    'sec.evasion': 'Evasion tricks',

    'det.high': 'High',
    'det.medium': 'Medium',
    'det.low': 'Low',

    'f.synOut': 'Send SYN to open a connection',
    'f.synackIn': 'SYN/ACK comes back -> the port is open',
    'f.ackComplete': 'Send ACK to complete the three-way handshake',
    'f.finAckClose': 'Send FIN/ACK to close the connection cleanly',
    'f.rstAckReject': 'RST/ACK comes back -> the port is closed (connection refused)',
    'f.rstInterrupt': 'Send RST to tear down the connection early (do not complete the handshake)',
    'f.finOut': 'Send a packet with only FIN set',
    'f.nullOut': 'Send a packet with no flags set',
    'f.xmasOut': 'Send a packet with FIN+PSH+URG all set',
    'f.udpOut': 'Send a UDP datagram',
    'f.icmpUnreach': 'ICMP Port Unreachable (type 3, code 3) comes back -> the port is closed',
    'f.timeoutRfc': 'No response (timeout) -> open on an RFC 793-compliant stack. A filter also stays silent, so it is open|filtered',
    'f.timeoutUdp': 'No response (timeout) -> open or filtered (open|filtered)',
    'f.rstAckIn': 'RST/ACK comes back -> the port is closed',

    'scan.tcp-connect.name': 'TCP Connect (full connect)',
    'scan.tcp-connect.summary': 'The most basic scan: it uses the OS `connect()` call to complete a full three-way handshake.',
    'scan.tcp-connect.pros': 'Needs no privilege (root/admin)\nEasy to implement in any OS or language\nGives a reliable open/closed verdict',
    'scan.tcp-connect.cons': 'Completes the connection, so it is the most likely to appear in the target\'s logs\nSlower than the other TCP scans',
    'scan.tcp-connect.priv': 'No privilege required (just calls `connect()`; nmap `-sT`)',
    'scan.tcp-connect.ids': 'It establishes a connection and then closes it, so it is recorded in the server\'s connection logs and is the easiest to notice.',

    'scan.tcp-syn.name': 'TCP SYN (half-open)',
    'scan.tcp-syn.summary': 'Sends SYN; if SYN/ACK comes back it judges the port open, then tears the connection down with RST. It never completes the three-way handshake.',
    'scan.tcp-syn.pros': 'Does not complete the connection, so it is less likely to appear in connection logs\nFaster than TCP Connect\nGives a reliable open/closed verdict',
    'scan.tcp-syn.cons': 'Needs privilege because it builds raw packets',
    'scan.tcp-syn.priv': 'Privilege required (raw socket; nmap `-sS`)',
    'scan.tcp-syn.ids': 'Historically called "half-open" or "stealth", but modern IDS/IPS detect half-open connections too (stealth is a historical name).',
    'scan.tcp-syn.evasion': 'It may be combined with decoys (`-D`), timing control (`-T`) or packet fragmentation (`-f`) to try to avoid detection.',

    'scan.fin.name': 'FIN',
    'scan.fin.summary': 'Sends a packet with only FIN set. An RFC 793-compliant stack stays silent when the port is open and returns RST/ACK when it is closed.',
    'scan.fin.pros': 'Sends no SYN, so it can slip past old IDS that only watch SYN, or simple filters',
    'scan.fin.cons': 'Stacks that do not follow RFC 793 (Windows, some Cisco, BSDI, OS/400, ...) return RST regardless of open/closed, so no verdict is possible\nWhen there is no response, open cannot be told apart from filtered (open|filtered)',
    'scan.fin.priv': 'Privilege required (nmap `-sF`)',
    'scan.fin.ids': 'Old IDS may miss it, but modern IDS detect this kind of irregular packet.',

    'scan.null.name': 'NULL',
    'scan.null.summary': 'Sends a packet with no flags set. The verdict logic is the same as FIN (open = no response, closed = RST/ACK).',
    'scan.null.pros': 'With no flags set, it can slip past filters that look for specific flags',
    'scan.null.cons': 'No verdict on stacks that do not follow RFC 793 (same as FIN)\nopen cannot be told apart from filtered when there is no response',
    'scan.null.priv': 'Privilege required (nmap `-sN`)',
    'scan.null.ids': 'A packet with no flags is rare in normal traffic, so it tends to match modern IDS signatures.',

    'scan.xmas.name': 'Xmas (FIN+PSH+URG)',
    'scan.xmas.summary': 'Sets FIN, PSH and URG at once (the packet looks "lit up" like a Christmas tree). The verdict is the same as FIN.',
    'scan.xmas.pros': 'Can slip past filters that do not expect this flag combination',
    'scan.xmas.cons': 'No verdict on stacks that do not follow RFC 793 (same as FIN)\nThe unusual flag combination is easy for IDS to detect',
    'scan.xmas.priv': 'Privilege required (nmap `-sX`)',
    'scan.xmas.ids': 'These flags are not normally set together, so it tends to match IDS signatures.',

    'scan.udp.name': 'UDP',
    'scan.udp.summary': 'Sends a UDP datagram. A closed port returns ICMP Port Unreachable (type 3, code 3); an open port usually stays silent, so it is judged open|filtered.',
    'scan.udp.pros': 'Can probe UDP services that TCP cannot see (DNS, SNMP, NTP, ...)',
    'scan.udp.cons': 'Often no response, so the verdict is uncertain\nVery slow when ICMP rate limiting kicks in',
    'scan.udp.priv': 'Privilege required (to receive ICMP; nmap `-sU`)',
    'scan.udp.ids': 'It can be detected by a burst of ICMP, or by UDP to ports that are rarely used.',

    'help.title': 'About this tool',
    'help.about.h': 'What this tool does',
    'help.about.p': 'Learn six port-scan methods by comparing their packet exchange and verdicts on the same screen. It performs no real scanning; everything is a simulation inside your browser.',
    'help.use.h': 'How to use',
    'help.use.1': 'Choose a scan method.',
    'help.use.2': 'Toggle the target port state (open / closed).',
    'help.use.3': 'Press "Play" to animate the packet exchange one step at a time.',
    'help.use.4': 'Read the timeline, explanation and IDS detection to see why the verdict is reached.',
    'help.judge.h': 'Reading the verdict',
    'help.judge.1': '**Open**: the port is open (judged reliably from the response)',
    'help.judge.2': '**Closed**: the port is closed (RST/ACK or ICMP Port Unreachable comes back)',
    'help.judge.3': '**Open|Filtered**: no response, so open cannot be told apart from filtered',
    'help.note.h': 'Notes',
    'help.note.p': 'FIN, NULL and Xmas only work on RFC 793-compliant stacks. Windows, some Cisco, BSDI, OS/400 and others return RST regardless of open/closed, so these methods cannot judge them. Scanning ports without permission may be prohibited by law or terms of service.',
    'help.sources.h': 'References',
    'help.sources.1': 'nmap official documentation (Port Scanning Techniques)',
    'help.sources.2': 'RFC 9293 (TCP), RFC 792 (ICMP)'
  };

  const MESSAGES = { ja, en };

  // ヘルプの組み立て方（見出し h、段落 p、箇条書き ul・ol）
  const HELP = [
    { type: 'h', key: 'help.about.h' }, { type: 'p', key: 'help.about.p' },
    { type: 'h', key: 'help.use.h' }, { type: 'ol', keys: ['help.use.1', 'help.use.2', 'help.use.3', 'help.use.4'] },
    { type: 'h', key: 'help.judge.h' }, { type: 'ul', keys: ['help.judge.1', 'help.judge.2', 'help.judge.3'] },
    { type: 'h', key: 'help.note.h' }, { type: 'p', key: 'help.note.p' },
    { type: 'h', key: 'help.sources.h' }, { type: 'ul', keys: ['help.sources.1', 'help.sources.2'] }
  ];

  function t(key, vars = {}, lang) {
    const dict = MESSAGES[lang || (globalThis.PsvI18n && globalThis.PsvI18n.lang) || 'ja'] || ja;
    let text = Object.prototype.hasOwnProperty.call(dict, key) ? dict[key] : key;
    for (const [k, v] of Object.entries(vars)) text = text.split(`{${k}}`).join(String(v));
    return text;
  }

  globalThis.PsvMessages = { MESSAGES, HELP, t };
})();
