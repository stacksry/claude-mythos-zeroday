# Contributing Guidelines

## Adding a New Vulnerability

1. Create a research file in `research/` using the naming convention: `YYYY-MM-DD_vuln-name.md`
2. Fill in the research template (see `docs/templates/`)
3. Add a row to the status table in `README.md`
4. Branch per vulnerability: `git checkout -b vuln/vuln-name`

## Commit Message Format

```
[type] short description

Types: research | exploit | mitigation | fix | report | tool
```

Example:
```
[mitigation] add rate-limiting patch for auth bypass
```
