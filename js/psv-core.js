// Port Scan Visualizer の計算部（DOM を使わない）。globalThis.PsvCore に置く
// - 6種のポートスキャン（TCP Connect・TCP SYN・FIN・NULL・Xmas・UDP）の、開いた/閉じたポートへのパケットの往来と判定
// - パケットの説明・利点欠点・IDS の記述は、キーで messages.js の辞書から引く（日英のため）
// すべてブラウザーの中の学習用で、実際のスキャンはしない
(() => {
  'use strict';

  const SCAN_IDS = ['tcp-connect', 'tcp-syn', 'fin', 'null', 'xmas', 'udp'];

  // 判定の種類（表示文言は messages の judge.* ）
  const JUDGE = { open: 'open', closed: 'closed', openFiltered: 'openFiltered' };

  // パケット1つ: dir（out スキャナー→標的、in 標的→スキャナー、timeout 無応答）、proto、flags（TCP）
  //   icmp（ICMP の type/code）、descKey（説明の辞書キー）
  // 各手法の open/closed のフレーム列と判定。SCANS[id].proto はこの手法が使う主なプロトコル
  const SCANS = {
    'tcp-connect': {
      proto: 'TCP',
      open: {
        judgement: JUDGE.open,
        frames: [
          { dir: 'out', proto: 'TCP', flags: ['SYN'], descKey: 'f.synOut' },
          { dir: 'in', proto: 'TCP', flags: ['SYN', 'ACK'], descKey: 'f.synackIn' },
          { dir: 'out', proto: 'TCP', flags: ['ACK'], descKey: 'f.ackComplete' },
          { dir: 'out', proto: 'TCP', flags: ['FIN', 'ACK'], descKey: 'f.finAckClose' }
        ]
      },
      closed: {
        judgement: JUDGE.closed,
        frames: [
          { dir: 'out', proto: 'TCP', flags: ['SYN'], descKey: 'f.synOut' },
          { dir: 'in', proto: 'TCP', flags: ['RST', 'ACK'], descKey: 'f.rstAckReject' }
        ]
      }
    },
    'tcp-syn': {
      proto: 'TCP',
      open: {
        judgement: JUDGE.open,
        frames: [
          { dir: 'out', proto: 'TCP', flags: ['SYN'], descKey: 'f.synOut' },
          { dir: 'in', proto: 'TCP', flags: ['SYN', 'ACK'], descKey: 'f.synackIn' },
          { dir: 'out', proto: 'TCP', flags: ['RST'], descKey: 'f.rstInterrupt' }
        ]
      },
      closed: {
        judgement: JUDGE.closed,
        frames: [
          { dir: 'out', proto: 'TCP', flags: ['SYN'], descKey: 'f.synOut' },
          { dir: 'in', proto: 'TCP', flags: ['RST', 'ACK'], descKey: 'f.rstAckReject' }
        ]
      }
    },
    fin: {
      proto: 'TCP',
      open: {
        judgement: JUDGE.openFiltered,
        frames: [
          { dir: 'out', proto: 'TCP', flags: ['FIN'], descKey: 'f.finOut' },
          { dir: 'timeout', proto: 'TCP', descKey: 'f.timeoutRfc' }
        ]
      },
      closed: {
        judgement: JUDGE.closed,
        frames: [
          { dir: 'out', proto: 'TCP', flags: ['FIN'], descKey: 'f.finOut' },
          { dir: 'in', proto: 'TCP', flags: ['RST', 'ACK'], descKey: 'f.rstAckIn' }
        ]
      }
    },
    null: {
      proto: 'TCP',
      open: {
        judgement: JUDGE.openFiltered,
        frames: [
          { dir: 'out', proto: 'TCP', flags: [], descKey: 'f.nullOut' },
          { dir: 'timeout', proto: 'TCP', descKey: 'f.timeoutRfc' }
        ]
      },
      closed: {
        judgement: JUDGE.closed,
        frames: [
          { dir: 'out', proto: 'TCP', flags: [], descKey: 'f.nullOut' },
          { dir: 'in', proto: 'TCP', flags: ['RST', 'ACK'], descKey: 'f.rstAckIn' }
        ]
      }
    },
    xmas: {
      proto: 'TCP',
      open: {
        judgement: JUDGE.openFiltered,
        frames: [
          { dir: 'out', proto: 'TCP', flags: ['FIN', 'PSH', 'URG'], descKey: 'f.xmasOut' },
          { dir: 'timeout', proto: 'TCP', descKey: 'f.timeoutRfc' }
        ]
      },
      closed: {
        judgement: JUDGE.closed,
        frames: [
          { dir: 'out', proto: 'TCP', flags: ['FIN', 'PSH', 'URG'], descKey: 'f.xmasOut' },
          { dir: 'in', proto: 'TCP', flags: ['RST', 'ACK'], descKey: 'f.rstAckIn' }
        ]
      }
    },
    udp: {
      proto: 'UDP',
      open: {
        judgement: JUDGE.openFiltered,
        frames: [
          { dir: 'out', proto: 'UDP', descKey: 'f.udpOut' },
          { dir: 'timeout', proto: 'UDP', descKey: 'f.timeoutUdp' }
        ]
      },
      closed: {
        judgement: JUDGE.closed,
        frames: [
          { dir: 'out', proto: 'UDP', descKey: 'f.udpOut' },
          { dir: 'in', proto: 'ICMP', icmp: { type: 3, code: 3 }, descKey: 'f.icmpUnreach' }
        ]
      }
    }
  };

  // IDS の検知性（level は high/medium/low。表示と説明の文言は messages の scan テキスト）。evasion を持つ手法
  const DETECTABILITY = {
    'tcp-connect': 'high', 'tcp-syn': 'medium', fin: 'low', null: 'low', xmas: 'medium', udp: 'low'
  };

  // TCP フラグの一覧（凡例の順）と色（CSS のトークンに対応）。色は画面でも使う
  const TCP_FLAGS = ['SYN', 'ACK', 'FIN', 'PSH', 'URG', 'RST'];

  // ポート番号を 1〜65535 で確かめる。範囲外や数でないときは { ok:false }
  // （画面は打ち直せるように、確定のときだけ既定へ戻す）
  function validatePort(value) {
    const s = String(value).trim();
    const n = Number.parseInt(s, 10);
    // 整数で、入力そのものが整数表記（先頭0や小数・指数を弾く）で、範囲内のときだけ通す
    if (!Number.isInteger(n) || String(n) !== s || n < 1 || n > 65535) return { ok: false, value: n };
    return { ok: true, value: n };
  }
  const DEFAULT_PORT = 80;

  // 指定した手法・状態（'open'/'closed'）のフレーム列と判定を返す
  function scenario(scanId, state) {
    const scan = SCANS[scanId];
    if (!scan) throw new Error(`unknown scan: ${scanId}`);
    return scan[state];
  }
  const getFrames = (scanId, state) => scenario(scanId, state).frames;
  const getJudgement = (scanId, state) => scenario(scanId, state).judgement;

  // パケットに表示する短いラベル（SYN+ACK、UDP、ICMP、NULL）
  function packetLabel(frame) {
    if (frame.proto === 'ICMP') return 'ICMP';
    if (frame.proto === 'UDP') return 'UDP';
    if (frame.flags && frame.flags.length) return frame.flags.join('+');
    return 'NULL';
  }

  globalThis.PsvCore = {
    SCAN_IDS, JUDGE, SCANS, DETECTABILITY, TCP_FLAGS, DEFAULT_PORT,
    validatePort, scenario, getFrames, getJudgement, packetLabel
  };
})();
