---
name: Easter Egg Suggestion
about: Propose a new Easter egg for the fake shell
title: "[EGG] "
labels: easter-egg, enhancement
assignees: ''
---

## The Trigger

*What command (or command pattern) would fire this Easter egg?*

```
[exact command or regex pattern]
```

**Would a real attacker type this?** Yes / No / Sometimes

*If "sometimes" or "no" — explain why it's still worth including.*

## The Effect

*What happens when the trigger fires? Describe the terminal output, timing, and any lasting effects on the session.*

```
[sketch of what the attacker sees]
```

**Duration:** approximately ___ seconds
**Does it close the session?** Yes / No
**Does it hang the session?** Yes / No / Until Ctrl+C

## Why It's Good

*What makes this Easter egg work? Great Easter eggs:*

- *Fire on something an attacker would naturally do (not a secret handshake)*
- *Stay convincing for at least 2 seconds*
- *Have a meaningful twist — not just an error message*
- *Match the overall tone (theatrical, slightly camp, technically convincing)*

*Explain how this egg meets those criteria.*

## MITRE Technique

*If this trigger corresponds to a real MITRE ATT&CK technique, list it here.*

Technique ID: `T[####.###]`
Name: ___
Tactic: ___

*If not applicable, write "N/A".*

## Implementation Notes

*Optional: sketch the implementation if you have ideas.*

```python
# in shell.py _dispatch():
if base == "your_command" and some_condition(args):
    await _fake_your_effect(write)
    return None

# module-level function:
async def _fake_your_effect(write) -> None:
    write("...\r\n")
    await asyncio.sleep(0.5)
    ...
```

## Are you willing to implement it?

- [ ] Yes, I'll open a PR
- [ ] I'd like help implementing it
- [ ] Just the idea — someone else can implement

---

*Before submitting: check [EASTER_EGGS.md](../../EASTER_EGGS.md) to make sure this trigger isn't already taken.*
