# HeaderGuard

A small, offline-first Python utility that reviews a **saved** HTTP response-header JSON file against a practical baseline. It never connects to a host or sends requests.

## Requirements

Python 3.9+; standard library only.

## Use

```bash
python -m headerguard.cli sample-headers.json
```

Input format:

```json
{"target":"sanitized label","headers":{"X-Content-Type-Options":"nosniff"}}
```

The `target` value is only a display label. Header policy depends on application needs, deployment, and browser support; findings are review prompts, not proof of security or a complete audit.

## Tests

```bash
python -m unittest discover -s tests -v
```

## AI assistance

This initial starter implementation was created with AI assistance. Review, test, and extend it before representing the work as your own.

## Scope and privacy

- Reads one local JSON file; makes no network connections.
- Do not commit real response captures containing cookies, tokens, internal hostnames, or other sensitive data.
- Use only data you are authorized to review.
