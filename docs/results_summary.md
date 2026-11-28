# Results summary

What each script under `gridcad/` measures, and the headline number it
produces. Raw outputs are in `results/`.

## Detection
- `protocol_detector.py` -- DNP3 protocol-feature detector on the real benign
  capture plus synthesized attack families (11 classes). Honest, identity-free
  accuracy 0.965 (campaign-blocked); leakage inflation only 0.031; a tree
  ensemble (RandomForest / XGBoost ~0.96) rather than a deep MLP. Cold- and
  warm-restart collapse into one class (confusion 0.516) -> 10 classes at
  macro-F1 0.989. Output: `protocol_detector_summary.json`.
- `replay_ablation.py` -- replay recall for the protocol detector, 0.967,
  versus 0.27 for a flow-statistics detector. Output:
  `replay_ablation_summary.json`.

## Physics safety gate
- `feeder_voltage_sweep.py` -- load sweep on IEEE 13/34/123; shows the
  authorized command band is feeder-dependent (safe on 13, unsafe on 34).
- `verifier_scaling.py` -- verifier cost vs feeder size, to IEEE 8500-node
  (~56 ms p50); no fixed authorization band is correct across feeders.
- `opendss_safety_engine.py` -- the OpenDSS consequence/rollback engine reused
  by the physics experiments and the real-DNP3 path.

## DNP3 protocol path
- `realdnp3_endtoend/run_multifeeder_endtoend.sh` -- a real dnp3_python/opendnp3
  master issues AnalogOutputFloat32 load-multiplier commands to a real DNP3
  outstation across IEEE13/34/123; authorized commands are applied to the
  isolated OpenDSS feeder, validated against ANSI Range A, and rolled back. All
  authorized commands are delivered over real DNP3; the physics oracle catches
  an authorized-but-unsafe command on IEEE34 (undervoltage), and the command-
  authorization band refuses the over-range 1.10 command before delivery.
  Output: `dnp3_opendss_endtoend_summary.json`. A single-station deep dive
  (over-range AnalogOutput rejection with full rollback detail) is in
  `dnp3_safety_gates_summary.json`. See `realdnp3_endtoend/README.md` to run.

## LLM authorization and necessity
- `prompt_leakage_rescore.py` -- re-scores the authorization task with the
  answer block removed; a deterministic rule ties the best model.
- `authorization_llm_only.py` / `authorization_physics_verifier.py` /
  `authorization_consolidation.py` -- consequence-aware authorization: the
  physics verifier reaches 1.00 with zero unsafe-allowed; the LLM alone does not.
- `operator_language_authorization.py` / `operator_language_necessity.py` --
  free-text operator authorization. Against a dependency parser and a
  hand-tuned negation/exclusion parser, the LLM (qwen2.5:7b, 0.857) wins on the
  compositional cases a fixed lexicon cannot enumerate (exception-to-exception,
  exclusion-set membership, distant scope). Output: `operator_language_authorization_summary.json`,
  `operator_language_necessity_summary.json`.
- `attack_vector_generalization.py` -- target selection generalizes across
  six attack vectors; raw master-safety does not (the case for the validator).

## Latency, cost, ablation
- `decision_latency.py` / `actuation_latency.py` -- full-path latency; the LLM
  synthesis (~1.9 s) dominates, the verifier adds <1 ms.
- `component_ablation.py` -- RAG is the most valuable LLM context; raw grid
  state belongs in the verifier, not the prompt.
- `operational_cost.py` -- false-positive isolation cost on IEEE 123 is
  role-dependent (a regulator isolation breaches ANSI; a monitor costs nothing).

## Robustness and resilience
- `adversarial_robustness.py` -- five attack families aimed at the master;
  the validator deploys 0 unsafe actions.
- `fault_injection.py` -- fault each pipeline stage over a real ONOS cluster;
  66 injections, 0 unsafe, fail-safe degradation and recovery throughout.
- `controller_failover.py` -- live ONOS mastership handoff, p50 ~2.5 s, data
  plane stays up.

## Explanations
- `faithfulness_judge.py` -- LLM-judge reliability on explanation faithfulness;
  gross violations caught, subtle physics contradictions missed.
- `faithfulness_verifier.py` -- a deterministic verifier that grounds the
  explanation against the structured decision record catches all four defect
  types at 1.00 (physics contradiction 0.25 -> 1.00), with zero position bias
  and a live-OpenDSS cross-check. Output: `faithfulness_verifier_summary.json`.

## Online mitigation retrieval
- `live_rag_prequential.py` -- prequential (test-then-train) evaluation of the
  retrieval store; +0.83 final-window over no-retrieval, leakage ~0.
