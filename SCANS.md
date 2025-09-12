# SCANS.md — Port Scan Visualizer 技術解説（6種類）

本ファイルは Port Scan Visualizer に対応した **6種類のスキャン手法**の技術解説と、  
**nmap / RustScan** による代表的な実行コマンド例をまとめたものです。  
> 注意：実環境でのスキャンは関係各所の許可を得た上で実施すること。


---

## 前提
- **ポート状態の判定**（一般的な目安）  
  - **Open**：接続/応答がそのサービス特有の形で返る  
  - **Closed**：RST（TCP）や ICMP Port Unreachable（UDP）  
  - **Filtered/Unknown**：ファイアウォールなどで無応答・フィルタリング
- **権限**  
  - `-sS`（SYN）など一部のスキャンは **原則 root/管理者権限** が必要。
- **OS/機器依存**  
  - FIN/NULL/Xmas の「無応答=Open推定」は **実装依存**。誤判定に注意。

---

## 1) TCP Connectスキャン

### 仕組み
- OSのソケットAPIで通常接続（3ウェイハンドシェイク）を試みる標準的スキャン。

```
Scanner → Target : SYN
Scanner ← Target : SYN/ACK → Open 判定（以降 ACK で接続成立、直後に FIN/RST で終了）
Scanner ← Target : RST → Closed 判定
```

### 特徴
- **長所**：最も確実（アプリ層まで到達）。権限不要（非特権ユーザーで可）。  
- **短所**：**ログに残りやすい**。IDS/IPSやアプリに痕跡が残る。

### nmap 例

```bash
# 単一ホストの標準スキャン（トップ1000ポート）
nmap -sT example.com

# 範囲指定＆サービス検出
nmap -sT -p 1-1024 -sV example.com
```

### RustScan 例

RustScan は 高速にポート発見 → 後段を nmap に委譲。-- 以降が nmap 引数。

```
# トップポート検出 → nmap に -sT を渡して詳細走査
rustscan -a example.com -- -sT -sV
```

## 2) TCP SYNスキャン
### 仕組み

SYN を送り、SYN/ACK なら RST を返して握手完了前に切断（ハーフオープン）。

```
Scanner → Target : SYN
Scanner ← Target : SYN/ACK   → Open 判定（Scanner は RST を返して中断）
Scanner ← Target : RST/ACK   → Closed 判定
（無応答/ICMP など）       → Filtered/Unknown
```

### 特徴

- 長所：Connectよりステルス性が高い、高速。
- 短所：権限が必要。FW/ミドルウェアの挙動差あり。

### nmap 例

```bash
# 半開スキャン（要root）
sudo nmap -sS example.com

# 範囲＆OS/サービス検出併用（権限必須オプションあり）
sudo nmap -sS -p 1-2000 -sV -O example.com
```

### RustScan 例

```bash
# RustScan で高速発見 → nmap に -sS を渡す（要root）
sudo rustscan -a example.com -- -sS -sV
```

## 3) FINスキャン

### 仕組み

- FIN フラグのみ送信。TCP仕様上、Closed ポートは RST を返すのが一般的。
- Open ポートは 黙殺（無応答）する実装が多いとされる（実装依存）。

```
Scanner → Target : FIN
Scanner ← Target : RST       → Closed
（無応答なら）               → Open 推定（または Filtered）
```

### 特徴

- 長所：一部でステルス性。ACL次第で通る場合あり。
- 短所：誤判定リスク。FW/OS依存が大きい。

### nmap 例

```bash
sudo nmap -sF example.com
sudo nmap -sF -p 1-1024 example.com
```

### RustScan 例

```bash
# RustScan → nmap に -sF を委譲
sudo rustscan -a example.com -- -sF
```

## 4) NULLスキャン

### 仕組み

- フラグなし（000000）のTCPパケットを送信。
- ClosedはRST、Openは無応答とされることが多い（実装依存）。

```
Scanner → Target : FLAGS=NULL
Scanner ← Target : RST       → Closed
（無応答なら）               → Open 推定（または Filtered）
```

### 特徴

- 長所：ステルス寄り。署名ベース検知をすり抜ける可能性。
- 短所：実装依存・FW依存が大きく、結果の解釈が難しい。

### nmap 例

```bash
sudo nmap -sN example.com
sudo nmap -sN -p 1-1024 example.com
```

### RustScan 例

```bash
sudo rustscan -a example.com -- -sN
```

## Xmasスキャン

### 仕組み

- FIN + PSH + URG を 点灯（Xmasツリー） させて送信。
- Closed は RST、Open は 無応答 とされることが多い（実装依存）。

```
Scanner → Target : FIN+PSH+URG
Scanner ← Target : RST       → Closed
（無応答なら）               → Open/Filtered 推定
```

### 特徴

- 長所：一部環境で効果。
- 短所：検知されやすい。FWに落とされやすく、誤判定も起きる。

### nmap 例

```bash
sudo nmap -sX example.com
sudo nmap -sX -p 1-2000 example.com
```

### RustScan 例

```bash
sudo rustscan -a example.com -- -sX
```

## UDPスキャン

### 仕組み

- UDPはコネクションレスかつフラグ無し。多くのClosedはICMP Port Unreachable を返す。
- Openは無応答の場合が多く（サービスによっては応答）、ICMP遮断下では Unknown が増える。

```
Scanner → Target : UDP datagram
Scanner ← Target : ICMP Port Unreachable  → Closed
（無応答 / 応答あり）                    → Open / Unknown（FWで遮断時）
```

### 特徴

- 長所：DNS(53)/NTP(123)/SNMP(161) 等の発見に有効。
- 短所：遅い、再送・レート制御が必要、ICMP遮断で判定が難しい。

### nmap例

```bash
# 代表ポートのみ（速め）
sudo nmap -sU -p 53,123,161 example.com

# 広範囲（時間がかかる）
sudo nmap -sU -p 1-1024 example.com

# サービス検出（UDPは -sV でも応答次第で精度に限界）
sudo nmap -sU -sV -p 53,123,161 example.com
```

### RustScan例

```bash
# RustScan で高速発見 → nmap に -sU を渡す
sudo rustscan -a example.com -- -sU -sV
```
