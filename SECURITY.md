# Security Policy

## Scope

MetasploitMCP exposes powerful Metasploit functionality through MCP. Treat the server and its credentials as security-sensitive infrastructure.

## Secure defaults

High-impact capabilities are disabled by default:

- active exploit/auxiliary/post execution
- session command execution and termination
- payload generation
- listener/job control

Enable only the capabilities required for your authorized lab or assessment.

## HTTP exposure

Bind HTTP/SSE to loopback unless remote access is explicitly required.

When the host is non-loopback, `MCP_REQUIRE_AUTH=auto` requires `MCP_AUTH_TOKEN`. Requests must use:

```
Authorization: Bearer <token>
```

Do not expose the HTTP endpoint directly to the public Internet. Prefer a private network or a hardened reverse proxy with TLS.

## Secrets

Never commit `MSF_PASSWORD`, `MCP_AUTH_TOKEN`, API keys, private keys, or generated payloads. Local `.env` files are ignored by Git.

Rotate any credential that has been exposed in chat, logs, shell history, screenshots, or public repositories.

## Reporting a vulnerability

Please do not disclose exploitable vulnerabilities in public issues. Use GitHub's private security reporting features for this repository when available, or contact the repository owner privately.
