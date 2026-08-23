# Security Policy

TokenTaint is a **defensive security** project: a firewall that stops prompt
injection from driving privileged actions in LLM agents. This document covers
how the project maps onto established security frameworks and how to report a
vulnerability.

## Threat coverage at a glance

| Framework | Mapping |
|---|---|
| **OWASP Top 10 for LLM Apps (2025)** | **LLM01 — Prompt Injection** (primary); **LLM02 — Sensitive Information Disclosure** and **LLM06 — Excessive Agency** (mitigated at the action boundary) |
| **MITRE ATLAS** | `AML.T0051` LLM Prompt Injection (direct & indirect); `AML.T0053` LLM Plugin Compromise — TokenTaint denies untrusted-origin instructions a path to plugins/tools |
| **CWE** | Transplants classic taint/injection defenses: `CWE-20` Improper Input Validation, `CWE-77/78` Command Injection, `CWE-829` Inclusion of Untrusted Functionality — reframed for the context window |
| **NIST AI RMF** | Supports **MAP/MEASURE/MANAGE** for agent action risk via explainable, audited allow/block decisions |
| **Zero Trust** | "Never trust, always verify" applied to *tokens*: no context is trusted by origin-blindness; every privileged action re-verifies the trust of its justification |
| **Object-capability security** | Privileged sinks gated by unforgeable, per-action, single-use capability tokens rather than ambient authority (`tokentaint.capabilities`) |
| **Information-flow control** | Trust lattice, join-on-derivation, and explicit **audited declassification** (Myers & Liskov) — a taint label rises only via a logged endorsement |
| **Message authentication (HMAC)** | Tamper-evident provenance labels (`tokentaint.integrity`); a forged or edited label fails verification and the guard fails closed |

## Security model (short version)

- **Trust boundary:** the provenance labeler at ingestion. Everything the agent
  reads from the outside world (web, docs, email, third-party tool output) is
  **untrusted by default**; trust is granted by *origin*, never inferred from
  content — so a payload cannot forge its own trust level.
- **Enforcement:** privileged tools ("sinks") are deny-by-default for
  untrusted-origin justifications. This is capability containment, not phrasing
  detection — it holds against obfuscation and paraphrase.
- **Auditability:** every allow/block/escalate decision is logged with the
  offending origin and reason, supporting incident review and detection
  engineering.

Full details: [`docs/threat_model.md`](docs/threat_model.md).

## Scope & responsible use

The injection payloads in this repository are synthetic or drawn from public
benchmarks and are used **only** to evaluate the author's own harness. Do not use
the scenario generators to attack systems you do not own or are not explicitly
authorized to test. This is a research/defensive tool, not an offensive one.

## Reporting a vulnerability

If you find a security issue in TokenTaint itself (e.g. a way to bypass the sink
guard, forge provenance, or launder taint that the docs claim is caught):

1. **Do not** open a public issue for an unpatched bypass.
2. Open a private [GitHub Security Advisory](https://github.com/Krishita17/TokenTaint/security/advisories/new)
   on this repository, or contact the maintainer.
3. Include a minimal reproduction (a `Scenario` or failing test is ideal) and the
   propagation strategy affected (`structural` / `attribution`).

Because taint laundering through trusted transforms is a **known, documented
limitation** (see the Tier-3 study), reports demonstrating *new* laundering
classes are especially welcome and will be credited.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | ✅ |

Security fixes land on `main`.
