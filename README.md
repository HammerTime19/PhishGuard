# 🛡️ PhishGuard — Phishing Detector

A Chrome extension that detects phishing websites in real time using 
URL heuristics, DOM analysis, and threat intelligence APIs.

## Features
- 22 detection checks across URL, page content, and API layers
- Google Safe Browsing integration
- VirusTotal (70+ engines)
- WHOIS domain age detection
- Smart rate limiting and domain caching

## Installation
1. Clone this repo
2. Add your API keys to `src/config.js` (see config.example.js)
3. Load unpacked in `chrome://extensions/`

## Stack
Chrome Manifest V3 · JavaScript ES Modules · Google Safe Browsing · VirusTotal · WHOIS API
