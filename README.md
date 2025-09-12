<!--
---
title: Port Scan Visualizer
category: network-security
difficulty: 2
description: Learn the differences between TCP/UDP scan methods with flag-focused animations.
tags: [port-scan, tcp, udp, visualization, education]
demo: https://ipusiron.github.io/port-scan-visualizer/
---
-->

![GitHub Repo stars](https://img.shields.io/github/stars/ipusiron/port-scan-visualizer?style=social)
![GitHub forks](https://img.shields.io/github/forks/ipusiron/port-scan-visualizer?style=social)
![GitHub last commit](https://img.shields.io/github/last-commit/ipusiron/port-scan-visualizer)
![GitHub license](https://img.shields.io/github/license/ipusiron/port-scan-visualizer)
[![GitHub Pages](https://img.shields.io/badge/demo-GitHub%20Pages-blue?logo=github)](https://ipusiron.github.io/port-scan-visualizer/)

**Day062 - 生成AIで作るセキュリティツール100**

# Port Scan Visualizer - ポートスキャン手法可視化ツール

代表的なポートスキャン手法（**TCP Connect / TCP SYN / FIN / NULL / Xmas / UDP**）を、  
**送受パケットの時系列**と**TCPフラグの違い**にフォーカスして学べる可視化ツールです。

直感的にパケットの流れを理解できるよう、アニメーションと解説を組み合わせています。
セキュリティ入門者から中級者まで、ポートスキャンの仕組みや検知ポイントを学ぶ教材として活用できます。

> ※このツールは学習目的の**疑似アニメーション**です。実ネットワークスキャンは実施しません。

---

## 🌐 デモページ

👉 **[https://ipusiron.github.io/port-scan-visualizer/](https://ipusiron.github.io/port-scan-visualizer/)**

ブラウザーで直接お試しいただけます。

---

## 📸 スクリーンショット

>![TCP SYNスキャンのデモ実行](assets/screenshot.png)  
>*TCP SYNスキャンのデモ実行*

---

## ✨ 特徴

- **代表的な6種類のスキャン手法を完全網羅**  
  TCP Connect（フルコネクト）/ TCP SYN（ハーフコネクト）/ FIN / NULL / Xmas / UDPの挙動を比較可能。  

- **TCPフラグを色分けした直感的な可視化**  
  SYN, ACK, FIN, PSH, URG, RSTを色別に強調表示し、フラグの組み合わせパターンが一目でわかる。  

- **リアルタイムパケットアニメーション**  
  スキャナー⇄ターゲット間のパケット移動をSVGアニメーションで再現。単一フラグは凡例と同色、複数フラグは区別色を使用。

- **ポート状態による動的シナリオ切り替え**  
  Open/Closedトグルで、同じスキャン手法でも異なる応答パターンを学習可能。  

- **🛡️ IDS検知コメンタリー機能**  
  各スキャン手法の検知性レベル（高/中/低）、検知シグネチャ、回避技術を専門家視点で解説。

- **ダーク/ライトモード対応**  
  🌙☀️ ワンクリック切り替えで、環境に合わせたテーマ選択が可能（設定自動保存）。

- **アニメーション速度調整**  
  0.2x〜2x の5段階でパケット送信速度を調整可能。初学者はスロー再生で詳細確認。

- **完全なセキュリティ対応**  
  CSP、XSS対策、入力検証を実装。GitHub Pages公開に適した安全設計。  

---

## 🎯 活用シナリオ

### セキュリティ研修や授業での教材

「SYNスキャンとConnectスキャンの違いは？」といった座学を説明するときに、アニメーションでTCPフラグの動きを見せることで直感的に理解できます。

学生や新人エンジニアが、紙の図解だけでは掴みにくい「フラグの違いによる応答の差」を即座に把握できます。

### インシデント対応チームの勉強会

IDS/IPSのログに「FINフラグを伴う通信」などが出た際に、どのスキャンに該当するのかを可視化して確認できます。

実際のトラフィックを流さなくても、疑似アニメーションで「なぜ検知されたか」を共有でき、認識合わせに役立ちます。  

---

## 🔧 技術解説

本ツールで扱う各種スキャン手法（TCP Connect / TCP SYN / FIN / NULL / Xmas / UDP）の技術的な仕組みやnmap/RustScanによる実行例は、以下の専用ドキュメントにまとめています。

➡️ [SCANS.md](./SCANS.md)

---

## 📁 ディレクトリー構成

```text
port-scan-visualizer/
├── .claude/
│   └── settings.local.json      # Claude Code設定
├── .git/                        # Git管理ファイル
├── assets/
│   └── screenshot.png           # スクリーンショット画像
├── .gitignore                   # Git除外設定
├── .nojekyll                    # GitHub Pages設定
├── CLAUDE.md                    # Claude Code プロジェクト設定
├── index.html                   # メインHTMLファイル
├── LICENSE                      # MITライセンス
├── README.md                    # プロジェクト説明書
├── SCANS.md                     # 技術解説ドキュメント
├── script.js                    # メインJavaScriptロジック
└── style.css                    # スタイルシート
```

### 主要ファイルの役割

- **index.html**: アプリケーションのUI構造、セキュリティヘッダー、テーマ切り替えボタン
- **script.js**: スキャン手法定義、SVGアニメーション、IDS検知ロジック、テーマ管理
- **style.css**: ダーク/ライトモードのスタイリング、レスポンシブデザイン、視覚効果
- **SCANS.md**: 各スキャン手法の技術詳細とnmap/RustScan実行例
- **CLAUDE.md**: AI開発支援用のプロジェクト設定とアーキテクチャ情報

----

## 📚 関連資料・リソース

### 書籍（私が関わったもの）

- [『ハッキング・ラボのつくりかた 完全版』](https://akademeia.info/?page_id=35502)…「Nmapの代表的なスキャン」（P.440-454）

---

## 📄 ライセンス

MIT License – 詳細は [LICENSE](LICENSE) を参照してください。

---

## 🛠 このツールについて

本ツールは、「生成AIで作るセキュリティツール100」プロジェクトの一環として開発されました。 
このプロジェクトでは、AIの支援を活用しながら、セキュリティに関連するさまざまなツールを100日間にわたり制作・公開していく取り組みを行っています。

プロジェクトの詳細や他のツールについては、以下のページをご覧ください。  

🔗 [https://akademeia.info/?page_id=42163](https://akademeia.info/?page_id=42163)
