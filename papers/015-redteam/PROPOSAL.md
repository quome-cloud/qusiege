> **Paper 015 proposal — Continuous red-teaming, IR & resilience.** Imported 2026-06-07 from the local
> outline `P13` (`ongoing-papers/papers/13-redteam-incident-resilience/`). Read with the
> [`ROADMAP.md`](../ROADMAP.md) deltas in mind: **monorepo** — features are `qfire`
> modules, not `haarf-*` crates or spin-out repos — and **confidential-enclave**
> production deployment, validated locally on Ollama via the OpenAI-compatible
> bridge. The threat model, hypotheses, experiments, datasets, and figures below
> are the pre-registered working plan; they are reconciled against the gateway as
> built at the feature-spec (stage 2) and paper-spec (stage 4) gates.

---

# Paper 13 — Continuous Red-Teaming, Incident Response & Resilience for Clinical AI Agents

**Crate:** `haarf-redteam` (+ `haarf-resilience`) · **New dataset:** HAARF-RedTeam · **Covers:** C3.1, C3.7, C3.8 · **Status:** outline

## Abstract

HAARF requires ongoing penetration testing & red-team exercises (C3.8), clinical
incident response & recovery (C3.7), and resilience to socio-technical disruption (C3.1)
— the operational security lifecycle. The original harness *is* a red-team tool but is
run manually, once. We generalize it into `haarf-redteam`, a continuous automated
red-teaming service that runs the full attack corpus (every other paper's dataset) on a
schedule and on every change, plus `haarf-resilience`, a chaos/fault-injection harness,
and an incident-response runbook engine that detects, contains, and recovers from
in-production attacks. We contribute **HAARF-RedTeam**, a continuously-growing, versioned
aggregate attack corpus + IR scenario suite, and report attack-discovery rate over time
and mean-time-to-contain.

## Stakeholders & expert-in-the-loop

Continuous red-teaming and incident response only stay clinically grounded and credible
with experts in the loop across security, resilience, and the bedside.

- **Offensive-security / AI red-team specialist** — designs and stress-tests the attack
  corpus so the loop-until-dry runner surfaces real adversarial-ML failure modes, not
  toy ones.
- **Security incident-response / SOC lead** — defines the detection→contain→recover
  runbooks the IR engine automates and validates that they reflect live SOC practice
  (C3.7).
- **Healthcare CISO** — owns the organizational security posture, accepts residual risk,
  and ensures continuous testing maps to enterprise controls and reporting obligations.
- **Clinical business-continuity / emergency-preparedness officer** — grounds the
  resilience scenarios in real disruption (downtime procedures, degraded-mode care) so
  fault injection reflects how care continues under failure (C3.1).
- **Site-reliability / chaos-engineering engineer** — designs the fault-injection
  experiments (latency, dependency loss, partition) and the safe-degradation invariants
  the gateway must hold.
- **Patient-safety officer** — translates each incident and reopened vulnerability into
  its potential clinical-harm impact, prioritizing what blast-radius reduction actually
  protects patients.
- **Frontline clinician** — tells us what a real in-production failure means at the
  bedside (a stalled or wrong agent response mid-encounter), grounding MTTC targets in
  care reality.
- **Regulatory / compliance officer** — ensures incident handling, forensic snapshots,
  and disclosure satisfy breach-notification and clinical-safety reporting requirements.

## Problem model

- **R1 Coverage decay** — new attack classes emerge; a one-time evaluation goes stale.
- **R2 Regression** — a config/model change reopens a previously-closed vulnerability.
- **R3 Incident handling** — a live attack is detected but containment/recovery is
  ad-hoc (no runbook) (C3.7).
- **R4 Socio-technical disruption** — dependency outage, latency storm, partial failure
  degrades the agent unsafely (C3.1).

## Research questions

- **RQ1** Does continuous red-teaming surface vulnerabilities a one-shot evaluation
  misses, and at what added cost?
- **RQ2** Can change-triggered regression red-teaming catch reopened vulnerabilities
  (R2) before deployment (links Paper 8 gate)?
- **RQ3** What detection→containment→recovery automation minimizes blast radius and
  mean-time-to-contain for live attacks (R3)?
- **RQ4** Does the gateway maintain safe degradation under injected socio-technical
  faults (R4)?

## Hypotheses

- **H1** Continuous/loop-until-dry red-teaming discovers ≥ K additional distinct
  vulnerabilities vs. one-shot, with discovery rate decaying toward a measured floor.
- **H2** Regression red-teaming on changes catches 100% of re-introduced known
  vulnerabilities at the deployment gate.
- **H3** Runbook automation reduces mean-time-to-contain by ≥ 50% vs. manual.
- **H4** Under fault injection (R4), the gateway holds fail-safe/availability invariants
  (no unsafe action, bounded degradation).

## Experiments → figures

- **E1 Continuous vs. one-shot (→ Fig 1):** cumulative distinct vulnerabilities found
  vs. red-team rounds (loop-until-dry curve).
- **E2 Regression catch (→ Fig 2):** reopened-vuln detection at the change gate.
- **E3 Incident response (→ Fig 3):** mean-time-to-detect / contain / recover,
  {manual, runbook-automated}.
- **E4 Chaos/resilience (→ Fig 4):** safe-invariant maintenance + availability under
  injected faults (latency, dependency loss, partition) — C3.1.
- **E5 Cost (→ Fig 5):** compute/token cost vs. coverage (the thoroughness dial).

## Datasets

**Public:**
- **MITRE ATLAS** — adversarial-ML tactic/technique taxonomy for coverage scoring.
- **AgentDojo / InjecAgent / AgentHarm / Agent Security Bench** — external attack
  batteries to fold into the corpus.
- Chaos-engineering methodology (fault-injection literature) — methods, not data.

**New — HAARF-RedTeam (the contribution):**
- A **versioned, growing aggregate attack corpus** unifying every HAARF paper's dataset
  (MA, Exfil, Poison, Policy, Device, SupplyChain, Consent, …) under one runner, tagged
  by control + ATLAS technique, with provenance for when each attack was added.
- An **incident-response scenario suite** (live-attack traces) with ground-truth
  contain/recover actions.
- A **fault-injection spec** for the resilience harness. Apache-2.0, synthetic.

## Validation & statistics

- Vulnerability-discovery curves with CIs; coverage measured against the ATLAS taxonomy
  (explicit "what we did NOT test" reporting — no silent caps).
- MTTD/MTTC/MTTR with CIs, manual vs. automated.
- Resilience invariants checked as pass/fail under each fault; any unsafe outcome
  root-caused.
- **Threats to validity:** automated red-teaming inherits its corpus's blind spots
  (hence the completeness-critic round); simulated incidents ≠ real SOC conditions.

## Rust components (`haarf-redteam`, `haarf-resilience`)

- **Continuous runner:** schedules + change-triggers the full corpus via `haarf-replay`;
  loop-until-dry with a completeness critic that proposes missing attack classes.
- **Regression gate:** hooks the Paper-8 deployment gate — a change that reopens any
  closed vulnerability is blocked.
- **IR engine:** detection rules over the live audit stream (Paper 2) → runbook actions
  (isolate agent, revoke capability token [Paper 1], trip circuit breaker, snapshot for
  forensics).
- **Chaos harness:** injects latency/faults/partitions at the gateway boundary to verify
  C3.1 resilience invariants.

## Server / proxy design

- Red-teaming runs against a **shadow/staging** gateway instance; the IR engine runs
  **inline** on production, consuming the signed audit stream and driving containment
  actions through existing layers (capability revocation, circuit breaker, fail-safe).
- Findings feed back into the corpus and the lifecycle passport (Papers 8/9).
- This paper is the **meta-layer**: it continuously exercises every other paper's
  controls and is how HAARF stays current after publication.

## Metrics

| Metric | Definition | Target |
|---|---|---|
| VDR | Distinct vulns found, continuous vs. one-shot | ≥ K extra |
| RGC | Regression catch rate at gate | 100% |
| MTTC | Mean-time-to-contain (automated) | ≥ 50% ↓ vs. manual |
| RIN | Resilience invariants held under faults | 100% |
| ATC | ATLAS technique coverage | report |

## Repo scaffold

```
haarf-redteam/
├── crates/haarf-redteam/           # continuous runner + regression gate + completeness critic
├── crates/haarf-resilience/        # chaos / fault-injection harness
├── crates/haarf-ir/                # incident-response detection + runbook engine
├── dataset/haarf-redteam/          # aggregate attack corpus + IR scenarios + fault spec
├── figures/
└── paper/
```
