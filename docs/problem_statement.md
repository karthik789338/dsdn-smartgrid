# GridCAD: formal problem statement

## System model
- **Plant.** A distribution feeder modeled in OpenDSS; state `x` is the vector of
  node voltages (pu) and losses. A control action is a DNP3 AnalogOutput load
  multiplier delivered to an outstation.
- **Control channel.** A DNP3 master (`10.0.0.1`) polls and commands outstations
  over an SDN data plane (ONOS controllers, OVS switches).
- **Adversary surface.** (a) DNP3 commands that may be over-range or
  authorized-but-physically-unsafe; (b) the LLM policy-synthesis channel, which
  proposes mitigations and is treated as untrusted (soft, attackable).
- **Defender.** GridCAD composes a *soft* proposer (the LLM) with a *hard* gate:
  a deterministic command-authorization validator and an OpenDSS physics oracle
  with automatic rollback, enforced through ONOS flow rules.

## Invariants
Let `A = [0.95, 1.05]` pu be ANSI Range A and `B = [1.005, 1.03]` the
command-authorization band.

- **I1 (control-channel availability).** No mitigation ever blocks the DNP3
  master `10.0.0.1`. *Enforced by:* the validator rejects any policy that would
  block the master; ONOS rules whitelist it.
- **I2 (voltage safety).** No action is left applied if it drives any node
  outside `A`. *Enforced by:* the OpenDSS physics oracle plus rollback.
- **I3 (authorization).** Every action applied to the plant was authorized
  against `B` by the deterministic validator. *Enforced by:* the command-layer
  gate before actuation.
- **I4 (over-range refusal).** Any command outside `B` is refused before it
  reaches the outstation. *Enforced by:* the command-layer gate.
- **I5 (recoverability).** Any applied action that violates `A` is automatically
  rolled back to the last verified-safe state within one control cycle.
  *Enforced by:* the rollback engine.
- **I6 (LLM containment).** No LLM-proposed mitigation is enforced unless it
  passes the validator and the physics oracle; the LLM is advisory and cannot
  bypass the hard gate. *Enforced by:* the validator + oracle as a mandatory
  gate on all proposals.

## Propositions
- **P1 (Safety).** Under I2+I3+I5 the set of applied plant states is contained
  in the Range-A-safe set, regardless of LLM proposals or authorized-looking
  attacker commands. The physics oracle is the backstop even when authorization
  alone would admit a command. *Evidence:* IEEE34 @ 1.02 is authorized yet the
  oracle catches the undervoltage and rolls back
  (`dnp3_opendss_endtoend_summary.json`).
- **P2 (Availability).** Under I1 the master's control channel stays reachable
  under every mitigation GridCAD deploys.
- **P3 (Attack containment).** An adversary who controls the LLM proposal channel
  (soft surface) cannot force an unsafe applied state, because I6 routes every
  proposal through the hard gate (I2/I3/I4). *Evidence:* IEEE13 @ 1.10 is refused
  at the command-authorization layer before delivery.
- **P4 (Detection complements enforcement).** The behavioural detector flags
  unseen attack families at mean 0.894 leave-one-family-out detection, but
  `master_impersonation` (0.0 LOFO) shows detection alone is insufficient; the
  physics oracle (I2) catches the physical consequence regardless of whether the
  family was seen in training. *Evidence:* `protocol_detector_summary.json`.
