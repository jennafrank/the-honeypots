---
name: Bug Report
about: Something in the fake shell broke, crashed, or behaved incorrectly
title: "[BUG] "
labels: bug
assignees: ''
---

## What happened?

*A clear description of the bug.*

## What did you expect to happen?

*What should have happened instead?*

## How to reproduce

**Trigger command:**
```
[exact command typed in the fake shell]
```

**Session context:**
- Username logged in as: `root` / `solana` / other: ___
- Current working directory when command ran: ___
- Was this an interactive session or exec mode (`ssh host cmd`)?

**Steps:**
1. Connect: `ssh [username]@[host]`
2. Run: `[commands leading up to the bug]`
3. Run: `[the command that broke]`
4. See: `[the broken output]`

## Actual output

```
[paste the terminal output here]
```

## Expected output

```
[paste what you expected to see, or describe it]
```

## Environment

- Deployment method: Docker Compose / bare Python / other: ___
- Python version: ___
- asyncssh version: ___
- Host OS: ___
- Any relevant `.env` settings: ___

## Logs

If available, paste the relevant lines from `data/logs/events.jsonl`:

```json
[paste log entries here]
```

## Additional context

*Anything else that might help diagnose this — was it intermittent, timing-related, specific to certain terminal emulators, etc.*
