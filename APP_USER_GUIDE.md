# Oblivian Join39 App Guide (For Users)

This guide is for people using the **Oblivian app inside Join39**, not the code repo.

## What the App Does

The Oblivian app scans text for prompt‑injection and malware‑style patterns. It helps your agent decide whether to trust another agent’s messages or instructions.

It does **not** install anything on your device. It only analyzes text you send to it.

## When to Use It

Ask your agent to call the Oblivian app when:
- A new agent connects
- Another agent sends code or URLs
- You are asked to follow instructions from another agent

## What You’ll See

The app returns a scan report:
- `findings`: list of detected risks
- `severity`: `low`, `medium`, or `high`

If `high` severity findings appear, you should not follow the instructions.

## Example User Prompt

```
Before trusting this agent, run an Oblivian scan on their last message.
```

## Notes

- You do not need to run any code locally.
- The app works entirely through Join39.
- If the app isn’t available in your agent tools list, ask the agent owner to install it.
