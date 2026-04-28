# Contributing to Sable Saint-Claire & The Honeypots

Thank you for wanting to make the honeypot more delightful and deceptive.

## How to Contribute

### Bug Reports

Use the [bug report template](.github/ISSUE_TEMPLATE/bug_report.md). Include the exact command that triggered the issue and what you expected vs. what happened.

### New Easter Eggs

This is the most fun kind of contribution. Use the [Easter egg suggestion template](.github/ISSUE_TEMPLATE/easter_egg_suggestion.md) to propose an idea, or implement it directly and open a PR.

**The bar for a good Easter egg:**

1. **Triggered by something an attacker would naturally do** — not a secret handshake only a contributor would know. Real attackers run `wget`, `rm -rf`, `passwd`. They don't run `xyzzy`.
2. **Proportional to intent** — a casual `ls` gets nothing. A `chmod +x` on a downloaded file is aggression. Calibrate the response.
3. **Terminally convincing for at least 2 seconds** — the best Easter eggs make the attacker genuinely believe something is happening before the twist.
4. **Logged** — every Easter egg should call `_log_command` and/or set `session.high_interest = True` so it surfaces in the dashboard.
5. **No real side effects** — the shell is entirely fake. Nothing should touch the host filesystem, network, or processes.

### Implementing an Easter egg

All shell logic lives in `honeypot/shell.py`. The pattern is:

```python
# 1. Write an async function at module level
async def _fake_your_thing(write) -> None:
    write("...convincing output...\r\n")
    await asyncio.sleep(0.5)
    # ... the twist ...

# 2. Intercept the trigger in FakeShell._dispatch()
if base == "your_command" and some_condition(args):
    await _fake_your_thing(write)
    return None
```

Key rules for `write()` calls:
- Use `\r\n` not `\n` — this is a raw terminal stream
- ANSI escape codes work: `\x1b[1;31m` = bold red, `\x1b[0m` = reset
- Hide/show cursor: `\x1b[?25l` / `\x1b[?25h`
- Clear screen: `\x1b[2J\x1b[H`

**If the Easter egg should end the session** (like the wallet gotcha does), set `self._close_session = True` before returning.

### Fake filesystem additions

Files and directories live in `honeypot/filesystem.py`. Add entries to:
- `DIRECTORY_TREE` — the dict of `path → [(name, is_dir), ...]`
- `FILES` — the dict of `path → content_string`

### MITRE tagging

If your Easter egg corresponds to a real MITRE technique, add a rule to `honeypot/mitre.py`:

```python
(re.compile(r"your_pattern", re.IGNORECASE),
 Technique("T1234.001", "Technique Name", "Tactic")),
```

## Code Style

- Python 3.10+, no type: ignore, no bare excepts
- `async def` for anything that sleeps or writes to the terminal
- Keep Easter egg functions at module level (not as class methods) — they're standalone theatrical sequences
- No comments explaining what the code does — only why if it's genuinely non-obvious

## Pull Request Checklist

- [ ] Easter egg triggers on something a real attacker would do
- [ ] Effect is convincing for at least 2 seconds
- [ ] Session is flagged (`session.high_interest = True`) if appropriate
- [ ] Command is logged via `_log_command`
- [ ] No real side effects on the host
- [ ] `\r\n` used in all `write()` calls
- [ ] EASTER_EGGS.md updated with the new trigger (no spoilers on the effect)
- [ ] docker-compose up --build tested locally
