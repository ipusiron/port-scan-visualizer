# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Port Scan Visualizer - Educational tool for visualizing different port scanning techniques (TCP Connect, TCP SYN, FIN, NULL, Xmas, UDP) with TCP flag animations and time-series packet flow. Part of "生成AIで作るセキュリティツール100" project (Day062).

## Architecture

### Core Structure
- **Frontend-only application** (no backend/build process)
- Static HTML/CSS/JavaScript served directly via GitHub Pages
- No external dependencies or frameworks
- CSP headers configured in `index.html:8-11`

### Data Model
The `SCANS` object (`script.js:77-293`) defines all scan types with:
- `name` - Display name
- `proto` - Protocol (TCP/UDP)
- `scenarios.open/closed` - Port state-specific packet sequences
  - `frames[]` - Array of packet objects with `dir`, `proto`, `flags[]`, `desc`
  - `judgement` - Result text (Open/Closed/Filtered)
- `summary.pros/cons` - Educational bullet points
- `ids` - IDS detection info (`detectability`, `signatures[]`, `evasion[]`, `comments`)

### Key Functions
- `animatePacket()` (`script.js:409-473`) - SVG packet animation between scanner/target
- `animateSequence()` (`script.js:475-501`) - Orchestrates full scan animation
- `renderTimeline()` (`script.js:515-523`) - Populates timeline list from frames
- `renderIDSCommentary()` (`script.js:544-579`) - Displays IDS detection info
- `sanitizeHTML()` (`script.js:36-40`) - XSS prevention for dynamic content

### Styling
- Dark/light theme via CSS variables (`style.css:1-24`)
- Flag colors defined in JS (`script.js:296-304`) and CSS outlines (`style.css:58-65`)
- Theme persisted to localStorage

## Development Notes

### Running Locally
Open `index.html` directly in browser or use any static server:
```bash
python -m http.server 8000
```

### Adding a New Scan Type
1. Add entry to `SCANS` object with `name`, `proto`, `scenarios`, `summary`, `ids`
2. Add `<option>` to `#scanSelect` in `index.html:29-36`
3. If new protocol, add flag styling in `style.css` and color in `flagColors`

### Security Considerations
- All user input sanitized via `sanitizeHTML()` before DOM insertion
- Port input validated via `validatePort()` (`script.js:43-49`)
- CSP prevents inline scripts and external connections