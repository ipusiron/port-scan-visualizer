# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Port Scan Visualizer - an educational tool for comparing six port-scan methods (TCP Connect, TCP SYN, FIN, NULL, Xmas, UDP) with the same packet exchange and verdicts. It performs no real scanning; everything runs in the browser. Part of the "生成AIで作るセキュリティツール100" project (Day062).

## Architecture

### Core structure
- Frontend-only application (no backend, no build step)
- Static HTML/CSS/JavaScript served via GitHub Pages
- No external dependencies or frameworks
- CSP configured in `index.html` (`connect-src 'none'`, `object-src 'none'`); meta X-Frame-Options / X-Content-Type-Options are not used because they have no effect as meta elements

### Files
- `js/psv-core.js` - DOM-free core: the `SCANS` data (6 methods x open/closed frames and verdicts), `DETECTABILITY`, `TCP_FLAGS`, `validatePort()`, `packetLabel()`. Exposed as `globalThis.PsvCore` and tested with `node --test`.
- `js/messages.js` - Japanese/English text dictionary and `t(key, vars, lang)`. Exposed as `globalThis.PsvMessages`.
- `js/i18n.js` - language selection and static-text substitution (`data-i18n` / `data-i18n-attr`). `globalThis.PsvI18n`.
- `js/theme.js`, `js/theme-init.js` - light/dark theme toggle and pre-render application. `globalThis.PsvTheme`.
- `js/app.js` - screen logic only: scan selection, SVG packet animation, timeline, explanation and IDS rendering, help modal, language/theme wiring.

### Data model
Each entry in `SCANS` (`js/psv-core.js`) has:
- `proto` - protocol (TCP/UDP)
- `open` / `closed` - port-state scenarios, each `{ judgement, frames[] }`
  - `frames[]` - packet objects with `dir` (`out`/`in`/`timeout`), `proto`, `flags[]`, optional `icmp`, and `descKey` (a dictionary key resolved by `messages.js`)
  - `judgement` - `open` / `closed` / `openFiltered`

### Styling
- Light-default color tokens, overridden for dark under `@media (prefers-color-scheme: dark) :root:not([data-theme="light"])` and `:root[data-theme="dark"]`
- TCP flag colors in CSS (`.flag[data-flag="…"]`); theme persisted to localStorage

## Development notes

### Running locally
Open `index.html` directly in a browser, or use any static server:
```bash
python -m http.server 8000
```

### Tests
```bash
npm test
```
Runs the core, HTML, messages, i18n, contrast, format and README checks. The same tests run on GitHub Actions (`.github/workflows/test.yml`).

### Adding a new scan method
1. Add an entry to `SCANS` in `js/psv-core.js` (`proto`, `open`, `closed`), add its id to `SCAN_IDS`, and set its `DETECTABILITY`.
2. Add the `scan.<id>.*` and any new `f.*` text to both `ja` and `en` in `js/messages.js`.
3. If a new protocol or flag is involved, add its color in `style.css`.

### Security considerations
- On-screen text is built with DOM APIs (`textContent`, `createElement`); no `innerHTML` or template-string HTML.
- Port input is validated via `validatePort()` in `js/psv-core.js` (integer in 1-65535).
- CSP prevents inline scripts and external connections.
