# HAARF-RedTeam — paper 015 corpus

Self-contained, fully synthetic, deterministic (seed=42), Apache-2.0. No PHI.
Regenerate:

```bash
python3 scripts/015-redteam/gen_redteam.py --seed 42
```

The generated `*.jsonl` are gitignored; only the generator and this README are
tracked. Schemas match `src/redteam/` serde exactly.

## Coverage & the built/unbuilt split (no silent caps)

015 is the program capstone: it exercises **every other paper's control**. Of the
13 target layers, **10 are built on master (001–011)** and **3 are not yet built
(012 lifecycle, 013 consent, 014 device)**. Unbuilt-layer attacks are **always
bypass** — this is reported as a coverage finding, never silently dropped. The
headline is the *operational* result (continuous discovery > one-shot, regression
caught, MTTC reduced, resilience invariants held), not a total-coverage claim.

| Control | Layers (built) | Layers (gap-tagged) |
|---------|----------------|---------------------|
| C1 | monitor | lifecycle |
| C2 | audit | — |
| C3 | firewall, admission, egress, retrieval | — |
| C4 | oversight | consent |
| C5 | identity | — |
| C7 | equity | — |
| C8 | policy | device |

## `corpus.jsonl` — `AttackRecord` per line

`{id, control:"C1".."C8", atlas:"AML.Txxxx", layer (lowercase), built:bool,
payload, expected_block:bool, seed_round:0, lineage:null}`

Built-layer payloads embed a block-signature (kept in sync with
`runner.rs::GatewayProbe::signatures`) so the modeled gateway blocks them at
round 0; the continuous runner's deterministic mutation operators evade the
signature at the attack's `evasion_round` (spread 1–6). 5 distinct vulnerabilities
(ATLAS techniques) per built layer, 4 per unbuilt layer; one canonical attack per
vulnerability. Distinct vuln-key = `(control, atlas, layer)`.

## `incidents.jsonl` — incident stream per line

`{stream_id, is_attack:bool, events:[{step, agent_id, attack_signature|null,
score}]}`. Half the streams inject a live attack (`attack_signature` set on a
window, `score` crossing 0.5 after a detection gap of 1–8 steps); half are benign
controls. Consumed by the IR engine (E3) — `respond()` per stream, automated vs
manual arms.

## `faults.jsonl` — fault scenario per line

`{id, arm:"production"|"validation", kind:"latency"|"dependency_loss"|"partition",
invariant:"no_unsafe_action"|"bounded_degradation", magnitude, fail_open:bool,
max_degradation}`. The **production** arm is the real fail-safe-closed gateway
(all invariants should hold); the **validation** arm plants broken gateways
(fail-open, or too-tight envelope) the harness must catch (E4).
