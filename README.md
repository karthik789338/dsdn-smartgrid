# DSDN-SmartGridLab / GridCAD

A software-defined networking testbed for DNP3 SCADA traffic, with a
consequence-aware mitigation layer (GridCAD) that pairs an LLM policy
proposer with a deterministic validator and an OpenDSS physics oracle.

This repository backs our IEEE Transactions on Smart Grid submission and
extends the original DSDN_SmartGridLab pilot (ONOS cluster + Mininet + DNP3
master/outstation). The testbed bring-up scripts are under `setup/`; the
resubmission experiments and the GridCAD pipeline are under `gridcad/`.

## What's here

    setup/        testbed bring-up: ONOS cluster, Mininet topology, DNP3
                  master/outstation, tshark capture, Ollama install
    dnp3/         minimal DNP3 master / outstation used in the testbed
    detection/    pilot attack detection + mitigation entry point
    gridcad/      the defense pipeline and the evaluation scripts behind
                  each table/figure in the paper
    results/      recorded metrics (JSON/CSV) for every experiment
    data/         benign DNP3 capture + the IEEE 13- and 123-node feeders
                  used by the physics experiments
    docs/         results summary and problem formulation

## Method, in one paragraph

A cloud detector flags a DNP3 attack flow; an LLM (local, via Ollama) proposes
a mitigation using a small retrieval store of past incidents; a deterministic
validator plus an OpenDSS power-flow solve checks the proposal against the
grid's physical limits (ANSI Range A, 0.95-1.05 pu) and the network invariants
(the DNP3 master at 10.0.0.1 is never blocked); ONOS then installs the approved
flow rules. The LLM is treated as an untrusted proposer -- nothing it suggests
is deployed unless the validator and the physics oracle both accept it.

## Setup

Tested on Ubuntu 22.04. Testbed components:

  - ONOS 2.2.1 + Atomix 3.1.5 (3-node cluster), Open vSwitch, Mininet
  - Ollama with phi4-mini, qwen2.5:7b, llama3.2:3b, gemma3:4b
  - OpenDSS (opendssdirect), tshark for DNP3 capture

```
bash setup/onos_cluster_setup.sh
bash setup/mininet_setup.sh
bash setup/llm_setup.sh          # or llm_setup_gpu.sh on a GPU box
bash setup/dnp3_setup.sh
python setup/topology_setup.py
```

Python dependencies:

```
pip install -r requirements.txt
python -m spacy download en_core_web_sm   # for the dependency-parse baseline
```

## Data

  - `data/benign_dnp3_23stations.pcap` -- benign DNP3 capture from the
    23-outstation testbed, used to seed the protocol detector.
  - `data/feeders/f13p`, `data/feeders/f123p` -- IEEE 13- and 123-node OpenDSS
    feeders used by the physics experiments.
  - The scaling study (IEEE 34- and 8500-node) uses the standard OpenDSS test
    feeders; drop the `electricdss-tst` tree under `data/feeders/`.
  - The flow-feature detector comparison uses the ITHACA DNP3 IDS dataset
    (Zenodo 7348493); download it separately.

## Running the experiments

Each script in `gridcad/` is standalone and writes its metrics to `results/`.
Run them from inside `gridcad/` so the shared modules (`opendss_safety_engine`,
`protocol_detector`, `faithfulness_judge`, `operator_language_authorization`)
import cleanly:

```
cd gridcad
python protocol_detector.py             # DNP3 protocol-feature detector
python feeder_voltage_sweep.py          # physics safety gate, per feeder
python operator_language_necessity.py   # LLM vs rule / dependency-parse baselines
python faithfulness_verifier.py         # explanation faithfulness as verification
python fault_injection.py               # controller/service resilience
...
```

Seeds are fixed in each script (1234 for the detector, 7 for the LLM
authorization studies), so re-runs reproduce the JSON already in `results/`.
See `docs/results_summary.md` for what each script measures.
