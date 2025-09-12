# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Port Scan Visualizer - Educational tool for visualizing different port scanning techniques (TCP Connect, TCP SYN, FIN, NULL, Xmas, UDP) with TCP flag animations and time-series packet flow.

## Architecture

### Core Structure
- **Frontend-only application** (no backend/build process)
- Static HTML/CSS/JavaScript served directly via GitHub Pages
- All scan logic in `script.js:15-102` (SCANS object)
- No external dependencies or frameworks

### Key Files
- `index.html` - Main UI structure with scanner/target nodes
- `script.js` - Scan definitions, timeline rendering, UI interactions
- `style.css` - Dark theme with scan-specific visual indicators

### Data Model
Each scan type in SCANS object contains:
- `frames[]` - Packet sequence with flags, direction, conditions
- `judgement` - Port state determination logic
- `summary` - Educational pros/cons for each scan method

## Development Notes

### Running Locally
Open `index.html` directly in browser or use any static server:
```bash
python -m http.server 8000
# or
npx serve .
```

### Key Implementation Details
- TCP flags visualized with color-coded outlines (`style.css:36-42`)
- Timeline dynamically rendered from frame data (`script.js:105-114`)
- Port state badge updates based on scan conditions (`script.js:134-141`)
- No actual network scanning - purely educational animations

### Future Enhancements (TODO)
- SVG packet movement animations
- IDS detection commentary
- Multi-port scan sequences
- Japanese/English language toggle