#!/usr/bin/env python3
"""Consolidate per-run real-DNP3 -> OpenDSS results into one summary JSON.
Usage: consolidate_summary.py <runs_dir> <output_json>"""
import json, os, sys, datetime
ROOT = sys.argv[1] if len(sys.argv) > 1 else 'results/realdnp3_runs'
OUT = sys.argv[2] if len(sys.argv) > 2 else 'results/dnp3_opendss_endtoend_summary.json'
PLAN = [('ieee13_safe','IEEE13',1.02,'authorized_safe'),
        ('ieee34_reject','IEEE34',1.02,'authorized_physics_reject'),
        ('ieee123_safe','IEEE123',1.02,'authorized_safe'),
        ('ieee13_overrange','IEEE13',1.10,'over_range_refused')]
def L(p): return json.load(open(p)) if os.path.exists(p) else None
runs = []
for tag, f, lm, mode in PLAN:
    d = os.path.join(ROOT, tag)
    r = L(os.path.join(d, 'result.json')) or {}
    c = L(os.path.join(d, 'received_command.json'))
    dv = bool(c); sa = r.get('safety_accepted'); rb = r.get('rollback_verified')
    b = r.get('baseline') or {}; a = r.get('applied') or {}
    auth = (1.005 <= lm <= 1.03)
    if mode == 'authorized_safe': ok = dv and sa is True and rb is True
    elif mode == 'authorized_physics_reject': ok = dv and sa is False and rb is True
    else: ok = (not dv)
    runs.append({'run': tag, 'feeder': f, 'requested_load_multiplier': lm, 'policy_mode_expected': mode,
        'command_authorized': auth, 'dnp3_delivered': dv, 'received_load_multiplier': (c or {}).get('load_multiplier'),
        'dnp3_schema': (c or {}).get('schema'), 'station_id': (c or {}).get('station_id'), 'port': (c or {}).get('port'),
        'safety_accepted': sa, 'rollback_verified': rb, 'pass': r.get('pass'),
        'physical_change_observed': r.get('physical_change_observed'), 'max_node_voltage_change_pu': r.get('max_node_voltage_change_pu'),
        'loss_change_kw': r.get('loss_change_kw'), 'baseline_v_pu': [b.get('voltage_pu_min'), b.get('voltage_pu_max')],
        'node_count': b.get('node_count'), 'applied_v_pu': [a.get('voltage_pu_min'), a.get('voltage_pu_max')],
        'applied_undervoltage_nodes': a.get('undervoltage_nodes'), 'applied_overvoltage_nodes': a.get('overvoltage_nodes'),
        'rollback_max_node_error_pu': r.get('rollback_max_node_error_pu'), 'reasons': r.get('reasons'),
        'gate_behaved_correctly': bool(ok)})
summ = {'experiment': 'GridCAD real-DNP3 to OpenDSS multi-feeder end-to-end',
    'description': 'Real dnp3_python/opendnp3 master issues AnalogOutputFloat32 load-multiplier commands to a real DNP3 outstation (two-process, station 7, port 21007). Authorized commands are applied to an isolated OpenDSS feeder, validated against ANSI Range A by the physics oracle, and automatically rolled back.',
    'dnp3_stack': 'dnp3_python/opendnp3, Python 3.10, two-process master+outstation, DirectOperate',
    'transport': 'real DNP3 TCP master 10.0.0.1 -> outstation 10.0.0.7:21007',
    'feeders_tested': ['IEEE13','IEEE34','IEEE123'], 'ansi_range_a_pu': [0.95,1.05], 'command_authorization_band': [1.005,1.03],
    'runs': len(runs), 'all_gates_behaved_correctly': all(x['gate_behaved_correctly'] for x in runs),
    'dnp3_delivered_for_authorized_commands': all(x['dnp3_delivered'] for x in runs if x['command_authorized']),
    'generated_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'results': runs,
    'notes': 'IEEE34@1.02 is command-authorized but the OpenDSS physics oracle detects undervoltage (<0.95 pu) and rolls back -- the physics backstop catching an authorized-but-unsafe action. IEEE13@1.10 is refused at the command-authorization layer (outside [1.005,1.03]) and never delivered. Single-station deep dive is in dnp3_safety_gates_summary.json.'}
json.dump(summ, open(OUT, 'w'), indent=2)
print('wrote', OUT, '| all_gates_correct=', summ['all_gates_behaved_correctly'], '| delivered_authorized=', summ['dnp3_delivered_for_authorized_commands'])
