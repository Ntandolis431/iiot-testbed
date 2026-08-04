# Security Policy

## ⚠️ This is a deliberately vulnerable research testbed

This repository is a **virtual IIoT / Industry 4.0 security testbed** built for academic
research into identifying and prioritizing vulnerabilities in industrial systems. It
**intentionally** contains insecure configurations so they can be studied and attacked in a
controlled lab. These are **design decisions, not defects**:

| Intentional weakness                     | Vulnerability category studied            |
|------------------------------------------|-------------------------------------------|
| Mosquitto `allow_anonymous true`         | Insecure communication / weak auth        |
| OpenPLC default login `openplc/openplc`  | Weak / default authentication             |
| FUXA editor authentication disabled      | Insecure interface / access control       |
| Lab-only passwords in `.env`             | Weak / exposed credentials                |

**Do not deploy this stack on any network you do not fully control.** All host ports are
bound to `127.0.0.1` and the components are meant to run on an isolated Docker network only.

## Reporting a vulnerability

If you find a security issue in the **tooling or scripts** here (as opposed to the
intentional weaknesses above) — for example an accidentally committed secret, or a flaw in
the build that could harm a user running it — please report it privately:

- Open a **GitHub Security Advisory** (Security → Advisories → Report a vulnerability), or
- Email the maintainer (see the repository profile).

Please do not open a public issue for a suspected secret leak; report it privately so it can
be rotated first.

## Secret handling

No real secrets are committed. Credentials are injected at runtime from a gitignored `.env`
(see `.env.example`). If you believe a real credential was ever committed, treat it as
compromised: it must be **rotated**, not merely deleted, because Git history is permanent.
