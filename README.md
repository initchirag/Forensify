# Forensify

Forensify is a browser-based artifact triage workspace. Uploaded files are processed locally in the browser; the app does not send their contents to a threat-intelligence service or analysis server.

## What the analysis does

- Computes MD5 from the uploaded bytes and SHA-1, SHA-256, and SHA-512 using the browser's Web Crypto API.
- Checks a small set of file signatures and calculates Shannon entropy across the file bytes.
- Scans likely-text artifacts with local regular expressions for candidate indicators and ATT&CK-related patterns.
- Parses several timestamp shapes from readable text into a heuristic event timeline.
- Creates HTML, JSON, and CSV report files from the computed results.

## Important limitations

- Indicator and ATT&CK results are rule matches, not malware verdicts. Confidence and severity are heuristic labels.
- No live threat feed, reputation lookup, YARA engine, memory-forensics engine, or native Windows event-log parser is connected.
- Binary files are hashed and profiled, but their embedded strings are not extracted or scanned. The text rules only run on files identified as likely text.
- Entropy can suggest compressed or encrypted data, but cannot distinguish that from benign content.
- The displayed last-modified timestamp and MIME type are browser/file metadata, not authenticated forensic provenance.
- Bundled examples are synthetic fixtures and must not be treated as incident evidence or verified threat intelligence.

## Run locally

```sh
npm install
npm run dev
```
