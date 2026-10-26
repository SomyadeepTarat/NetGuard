"""Reproducible ablations. Default data is SYNTHETIC FEATURE FIXTURES, not a benchmark dataset.

Use --manifest for session-separated PCAP data. Test labels never fit or calibrate
the fusion reference. Reports include abstentions and binary detection metrics.
"""
import argparse
from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path
import time

import numpy as np
from backend.ml.algorithms import build_classifier, build_novelty_detector, session_calibration_folds

from backend.ml.evidence_fusion import EvidenceFusionEngine, FusionConfig
from backend.ml.detector import baseline
from backend.ml.features import FEATURES
from backend.ml.replay import replay_stream, ReplayTelemetry


def fixture_row(rng, timestamp, kind='BENIGN'):
    degree = 2
    values = [rng.uniform(35, 55), rng.uniform(1500, 2500), 2, degree,
              rng.uniform(0.5, 1.5), rng.uniform(0, .03), rng.uniform(.35, .55),
              rng.uniform(100, 200), rng.uniform(.05, .15), 0, rng.uniform(.08, .15), rng.uniform(.8, 1)]
    edges = ['server-a|443|TCP', 'resolver|53|UDP']
    if kind == 'PORT_SCAN':
        values[2], values[4], values[11] = rng.uniform(20, 40), rng.uniform(4, 8), 0
    elif kind == 'SYN_FLOOD':
        values[4], values[11], values[6] = rng.uniform(40, 100), 0, 0
    elif kind == 'TRAFFIC_FLOOD':
        values[1], values[8] = rng.uniform(90000, 150000), .95
    elif kind == 'PEER_CHANGE':
        # Marginal traffic volumes remain normal; the source's service edges change.
        edges = ['new-peer-a|445|TCP', 'new-peer-b|3389|TCP']
    elif kind == 'SLOW_SHIFT':
        values[1], values[7] = rng.uniform(4000, 5000), rng.uniform(300, 400)
    elif kind == 'MISSING_RESPONSES':
        values[6], values[11], values[5] = 0, 0, .5
    elif kind == 'BENIGN_BURST':
        values[1] = 15000
    return {'source': '10.0.0.10', 'timestamp': timestamp, 'features': dict(zip(FEATURES, values)),
            'graph_context': {'out_degree': degree, 'edges': edges}, 'quality': {}}


def synthetic_data(seed, config):
    rng = np.random.default_rng(seed)
    fit = [fixture_row(rng, i * 5) for i in range(config.fit_windows)]
    calibration = [fixture_row(rng, 1000 + i * 5) for i in range(config.calibration_windows)]
    # Supervised baseline gets labelled attacks, while fusion/IF use benign only.
    supervised = [(fixture_row(rng, i * 5, label), label) for label in
                  ('BENIGN', 'PORT_SCAN', 'SYN_FLOOD', 'TRAFFIC_FLOOD') for i in range(64)]
    tests = []
    for scenario in ('BENIGN', 'PORT_SCAN', 'SYN_FLOOD', 'TRAFFIC_FLOOD', 'PEER_CHANGE', 'SLOW_SHIFT', 'MISSING_RESPONSES', 'TRANSIENT_BURST'):
        rows = []
        for i in range(30):
            attack = scenario in ('PORT_SCAN', 'SYN_FLOOD', 'TRAFFIC_FLOOD', 'PEER_CHANGE', 'SLOW_SHIFT') and i >= 8
            kind = scenario if (attack or scenario == 'MISSING_RESPONSES') else 'BENIGN'
            if scenario == 'TRANSIENT_BURST' and i in (9, 20):
                kind = 'BENIGN_BURST'
            rows.append((fixture_row(rng, 5000 + i * 5, kind), attack))
        tests.append({'session': f'{seed}-{scenario}', 'scenario': scenario, 'rows': rows,
                      'note': 'Missing-response fixtures simulate observation ambiguity, labelled non-attack.'})
    return fit + calibration, supervised, tests, {'scope': 'SYNTHETIC_FEATURE_FIXTURES', 'seed': seed}


def manifest_data(path, config):
    path = Path(path)
    sessions = json.loads(path.read_text())
    seen_ids, seen_paths, seen_hashes = set(), set(), set()
    fit, calibration, supervised, tests, fingerprints = [], [], [], [], []
    for session in sessions:
        pcap = (path.parent / session['pcap']).resolve()
        sid, split, label = session['session'], session['split'], session['label']
        if sid in seen_ids or pcap in seen_paths or split not in ('train', 'validation', 'test'):
            raise ValueError('Sessions and PCAP paths must be unique and have valid splits')
        seen_ids.add(sid)
        seen_paths.add(pcap)
        fingerprint = hashlib.sha256(pcap.read_bytes()).hexdigest()
        if fingerprint in seen_hashes:
            raise ValueError('Duplicate PCAP content would leak evidence across sessions/splits')
        seen_hashes.add(fingerprint)
        telemetry = ReplayTelemetry()
        rows, last = [], {}
        for row in replay_stream(pcap, telemetry=telemetry):
            if session.get('source') and row['source'] != session['source']:
                continue
            if row['timestamp'] - last.get(row['source'], -float('inf')) >= config.interval_seconds:
                rows.append(row)
                last[row['source']] = row['timestamp']
        if split == 'train':
            supervised.extend(({**row, 'training_session': sid}, label) for row in rows)
            if label == 'BENIGN':
                fit.extend(rows)
        elif split == 'validation' and label == 'BENIGN':
            calibration.extend(rows)
        elif split == 'test':
            tests.append({'session': sid, 'scenario': label, 'rows': [(row, label != 'BENIGN') for row in rows],
                          'note': 'Session-wide label; mixed captures require separate onset annotations.'})
        fingerprints.append({'session': sid, 'sha256': fingerprint, 'split': split,
                             'source_packets': telemetry.source_packets, 'retained_packets': telemetry.retained_packets})
    if len(fit) < config.fit_windows or len(calibration) < config.calibration_windows or not tests:
        raise ValueError(f'Need >= {config.fit_windows} benign train windows, >= {config.calibration_windows} benign validation windows, and held-out test sessions')
    return fit[:config.fit_windows] + calibration[:config.calibration_windows], supervised, tests, {
        'scope': 'USER_SUPPLIED_PCAP_SESSION_LABELS', 'manifest_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
        'captures': fingerprints}


def evaluate(reference, supervised, tests, metadata, config):
    raw = lambda row: [row['features'][f] for f in FEATURES]
    X = [raw(row) for row, _ in supervised]
    labels = [label for _, label in supervised]
    groups = [row.get('training_session') for row, _ in supervised]
    cv = session_calibration_folds(X, labels, groups) if all(g is not None for g in groups) else 3
    classifier = build_classifier(cv=cv)
    classifier.fit(X, labels)
    novelty = build_novelty_detector(config.fit_windows)
    novelty.fit([raw(row) for row in reference[:config.fit_windows]])
    variants = {'fusion_full': config, 'fusion_without_graph': replace(config, graph_enabled=False),
                'fusion_without_temporal': replace(config, temporal_enabled=False),
                'fusion_without_visibility': replace(config, visibility_enabled=False)}
    details = []
    for session in tests:
        engines = {name: EvidenceFusionEngine(cfg) for name, cfg in variants.items()}
        for engine in engines.values():
            engine.fit_reference(reference, metadata['scope'])
        stats = {name: {'tp': 0, 'fp': 0, 'tn': 0, 'fn': 0, 'abstentions': 0, 'false_alerts': 0, 'seconds': 0, 'first_detection_delay_seconds': None}
                 for name in ['rules', 'rbf_svm', 'novelty_lof', *variants]}
        rows = session['rows']
        last_false = {name: {} for name in stats}
        # Union of benign observation windows, not number of source windows.
        exposure, covered_until = 0.0, -float('inf')
        for timestamp in sorted({row['timestamp'] for row, actual in rows if not actual}):
            exposure += max(0, timestamp - max(timestamp - 5.0, covered_until))
            covered_until = max(covered_until, timestamp)
        attack_start = next((r['timestamp'] for r, label in rows if label), None)
        for row, actual in rows:
            for name in stats:
                start = time.perf_counter()
                abstain = False
                if name == 'rules':
                    alert = baseline(row['features']) != 'BENIGN'
                elif name == 'rbf_svm':
                    probabilities = classifier.predict_proba([raw(row)])[0]
                    alert = classifier.classes_[int(probabilities.argmax())] != 'BENIGN' and max(probabilities) >= .8
                elif name == 'novelty_lof':
                    alert = novelty.predict([raw(row)])[0] == -1
                else:
                    result = engines[name].score(row)
                    abstain = result['is_anomalous'] and result['visibility']['status'] == 'SENSITIVE'
                    alert = result['is_anomalous'] and not abstain
                s = stats[name]
                s['seconds'] += time.perf_counter() - start
                s['abstentions'] += int(abstain)
                s['tp' if actual and alert else 'fn' if actual else 'fp' if alert else 'tn'] += 1
                if not actual and alert and row['timestamp'] - last_false[name].get(row['source'], -float('inf')) >= 10:
                    s['false_alerts'] += 1
                    last_false[name][row['source']] = row['timestamp']
                if actual and alert and s['first_detection_delay_seconds'] is None:
                    s['first_detection_delay_seconds'] = row['timestamp'] - attack_start
        for name, s in stats.items():
            s['precision'] = s['tp'] / max(s['tp'] + s['fp'], 1)
            s['recall'] = s['tp'] / max(s['tp'] + s['fn'], 1)
            s['f1'] = 2 * s['tp'] / max(2 * s['tp'] + s['fp'] + s['fn'], 1)
            s['windows_per_second'] = len(rows) / max(s.pop('seconds'), 1e-9)
            s['benign_window_false_positive_rate'] = s['fp'] / max(s['fp'] + s['tn'], 1)
            s['benign_observation_seconds'] = exposure
            s['false_alerts_per_benign_hour'] = s['false_alerts'] * 3600 / exposure if exposure else None
            details.append({'session': session['session'], 'scenario': session['scenario'], 'method': name, **s})
    return {'metadata': metadata, 'config': asdict(config), 'results': details}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest')
    parser.add_argument('--output', default='artifacts/research/fusion_evaluation.json')
    args = parser.parse_args()
    config = FusionConfig()
    runs = []
    for seed in ([None] if args.manifest else [11, 23, 37]):
        reference, supervised, tests, metadata = manifest_data(args.manifest, config) if args.manifest else synthetic_data(seed, config)
        runs.append(evaluate(reference, supervised, tests, metadata, config))
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    report = {'version': 'fusion-ablation-v1', 'scope': runs[0]['metadata']['scope'], 'runs': runs,
              'interpretation': 'Known components, proposed integration; no priority claim. Default fixtures validate mechanisms, not real-world efficacy. Abstentions count as missed attacks for recall. Baseline SVM threshold=.8 fixed a priori. Timings include Python overhead.',
              'limitations': ['No claim of outperforming modern NIDS on public datasets.',
                             'No guaranteed false-alarm bound for dependent traffic or heuristic CUSUM.',
                             'Session-level labels cannot measure true attack onset in mixed captures.']}
    output.write_text(json.dumps(report, indent=2))
    reference_path = output.with_name('fusion_reference.json')
    reference_path.write_text(json.dumps({'config': asdict(config), 'scope': metadata['scope'], 'rows': reference}, indent=2))
    print(f'{report["scope"]}: {len(runs)} runs; report={output}; reference={reference_path}')


if __name__ == '__main__':
    main()
