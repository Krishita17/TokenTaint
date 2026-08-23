# TokenTaint — Threat Model

## Summary

TokenTaint defends the **action boundary** of an LLM agent: the moment a
privileged tool ("sink") is about to fire. It assumes prompt injection will
happen — that untrusted content *will* contain hidden instructions the model
*will* be tempted to follow — and it makes those instructions structurally
incapable of triggering a privileged action on their own, regardless of how they
are phrased.

## Attacker capability

The attacker **controls untrusted content the agent will ingest**:

- web pages the agent fetches,
- documents / RAG results it retrieves,
- emails or messages it reads,
- outputs of third-party tools it calls.

The attacker can write arbitrary text in that content, including text crafted to
look like system prompts, user messages, or trusted tool output, and can
obfuscate or encode it.

The attacker **does not** control:

- the user's direct instructions in the chat interface,
- the harness / runtime,
- the provenance labeler (labels are assigned at ingestion, out of reach),
- the trust table or the sink declarations.

## Attacker objective

Cause the agent to invoke a **privileged sink** on the attacker's behalf:

- exfiltrate data (`send_email`, network egress),
- move money (`make_payment`),
- execute code (`execute_code`),
- persist changes (`write_file`).

## Trust assumptions

- **Harness and labeler are trusted.** Provenance is assigned by the code that
  fetched/received the content, based on *where it came from*, never parsed from
  the content itself. Content therefore cannot forge its origin.
- **The LLM is untrusted-but-not-malicious.** It may be fooled by an injection
  (that is expected), but it is not itself the adversary and does not collude.
- **Trust is ordered and monotone under composition.** A value derived from
  multiple sources is no more trusted than its least-trusted input
  (information-flow join). This is what makes taint survive the model's own
  transforms.

## What TokenTaint guarantees

For any proposed sink call, if **every** span that justifies the call fails to
clear the sink's required trust level, the call is blocked (or escalated to the
human, who is a trusted source and may clear it). Because the decision depends
on **origin**, not on recognizing attack phrasing:

- direct, indirect (second-order via tool output), and obfuscated injections are
  handled identically — rewording does not help the attacker;
- the guarantee holds against payloads never seen before (no signature list).

## What TokenTaint does *not* claim

- **Not general model correctness.** It does not stop the model from being wrong,
  only from letting untrusted text *drive a privileged action*.
- **Sinks must be enumerable.** If a dangerous capability is not declared as a
  sink, it is not protected. Enumerating sinks is the integrator's job.
- **Taint laundering is a known hard case.** An attacker who launders an
  instruction through a *trusted* transform — e.g. gets a first-party
  summarizer to restate "email the files" as if it were the summary's own
  conclusion, severing the provenance chain — can defeat **attribution-based**
  propagation. **Structural** propagation resists this (the laundered *data*
  still flows to the sink), but at a higher false-block cost. This tension is
  measured directly in the Tier-3 laundering study (`results/laundering.json`,
  `docs/figures/fig4_laundering.png`) and is honest **future work**, not a
  solved problem.
- **Availability is out of scope.** A determined attacker can cause *blocks*
  (denial of the agent's usefulness) by planting injections everywhere; that is
  a utility cost, not a confidentiality/integrity breach.

## Ethics & scope

TokenTaint is a **defensive** tool. The injection payloads in this repository
are synthetic or drawn from public benchmarks, are used solely to evaluate the
author's own harness, and target no third-party system. Do not use the generator
to attack systems you do not own or are not authorized to test.
