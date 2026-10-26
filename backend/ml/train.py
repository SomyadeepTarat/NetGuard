"""Session-separated training, validation threshold selection, and held-out evaluation."""
import json
import time
from pathlib import Path
import joblib
import numpy as np
import sklearn
from backend.ml.algorithms import build_classifier, CLASSIFIER_ALGORITHM, session_calibration_folds
from sklearn.metrics import classification_report, confusion_matrix
from backend.ml.features import FEATURES, SCHEMA
from backend.ml.replay import replay
from backend.ml.detector import baseline, Detector


def load_manifest(path):
    path = Path(path)
    sessions = json.loads(path.read_text())
    seen, files = set(), set()
    labels = {'BENIGN', 'PORT_SCAN', 'SYN_FLOOD', 'TRAFFIC_FLOOD'}
    for session in sessions:
        resolved = (path.parent/session['pcap']).resolve()
        if session['session'] in seen or resolved in files:
            raise ValueError('Each capture/session must occur in exactly one split')
        if session['split'] not in ('train', 'validation', 'test') or session['label'] not in labels:
            raise ValueError('Invalid split or label')
        seen.add(session['session'])
        files.add(resolved)
        session['path'] = resolved
    if {s['split'] for s in sessions} != {'train', 'validation', 'test'}:
        raise ValueError('Manifest requires train, validation, and test sessions')
    return sessions


def samples(sessions, split, drop_rate=0):
    rows, labels, ids = [], [], []
    for session in sessions:
        if session['split'] == split:
            for row in replay(session['path'], drop_rate=drop_rate):
                if session.get('source') and row['source'] != session['source']:
                    continue
                rows.append(row)
                labels.append(session['label'])
                ids.append(session['session'])
    if not rows:
        raise ValueError(f'No usable windows in {split}')
    return rows, labels, ids


def matrix(rows):
    return [[r['features'][name] for name in FEATURES] for r in rows]


def metrics(truth, predictions, rows, ids, sessions):
    benign = [i for i, label in enumerate(truth) if label == 'BENIGN']
    # Exposure = sum of actual observation intervals from benign sessions.
    benign_seconds = 0
    delays = []
    for session in sessions:
        indexes = [i for i, value in enumerate(ids) if value == session['session']]
        if not indexes:
            continue
        times = [rows[i]['timestamp'] for i in indexes]
        if session['label'] == 'BENIGN':
            benign_seconds += max(times)-min(times)+1
        else:
            hits = [rows[i]['timestamp'] for i in indexes if predictions[i] == truth[i]]
            delays.append({'session': session['session'],
                           'seconds_from_capture_start': min(hits)-(min(times)-1) if hits else None})
    # Alerts use 10-second suppression per source and predicted class, matching streaming.
    last = {}
    false_alerts = 0
    for i in benign:
        label = predictions[i]
        if label not in ('BENIGN', 'UNCERTAIN'):
            key = (ids[i], rows[i]['source'], label)
            t = rows[i]['timestamp']
            if t-last.get(key, float('-inf')) >= 10:
                false_alerts += 1
                last[key] = t
    return {'classification': classification_report(truth, predictions, output_dict=True, zero_division=0),
            'confusion_labels': sorted(set(truth) | set(predictions)),
            'confusion_matrix': confusion_matrix(truth, predictions, labels=sorted(set(truth) | set(predictions))).tolist(),
            'false_alerts': false_alerts, 'benign_observation_seconds': benign_seconds,
            'false_alerts_per_hour': false_alerts*3600/benign_seconds if benign_seconds else None,
            'detection_delays': delays}


def train(manifest, output):
    sessions = load_manifest(manifest)
    train_rows, y, train_ids = samples(sessions, 'train')
    validation, vy, _ = samples(sessions, 'validation')
    if set(y) != {'BENIGN', 'PORT_SCAN', 'SYN_FLOOD', 'TRAFFIC_FLOOD'}:
        raise ValueError('Training requires benign and all three attack classes')
    folds = session_calibration_folds(matrix(train_rows), y, train_ids)
    model = build_classifier(cv=folds)
    model.fit(matrix(train_rows), y)
    probabilities = model.predict_proba(matrix(validation))
    labels = model.classes_[probabilities.argmax(axis=1)]
    scores = probabilities.max(axis=1)
    # Choose threshold on validation only, maximizing attack F1 with benign FP penalty.
    options = []
    for threshold in (.6, .7, .8, .9, .95):
        positive = (labels != 'BENIGN') & (scores >= threshold)
        actual = np.array(vy) != 'BENIGN'
        tp, fp, fn = sum(positive & actual), sum(positive & ~actual), sum(~positive & actual)
        options.append((2*tp/max(2*tp+2*fp+fn, 1), threshold))
    threshold = max(options)[1]
    scope = 'synthetic-demo' if any(s.get('scope') == 'synthetic-demo' for s in sessions) else 'user-supplied; independently validate'
    bundle = {'schema': SCHEMA, 'features': FEATURES, 'model': model, 'algorithm': CLASSIFIER_ALGORITHM,
              'calibration': 'sigmoid; capture-grouped cross-validation within training split',
              'threshold': threshold, 'scope': scope, 'training_sessions': [s['session'] for s in sessions if s['split'] == 'train'],
              'score_note': 'Uncalibrated classifier score, not probability of a real attack'}
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, output)
    detector = Detector(output)
    report = {'scope': scope, 'algorithm': CLASSIFIER_ALGORITHM, 'sklearn_version': sklearn.__version__,
              'calibration': bundle['calibration'],
              'delay_note': 'Seconds from first retained capture packet; session-wide attacks, not mixed-traffic onset latency', 'threshold': threshold, 'features': FEATURES,
              'train_windows': len(y), 'validation_windows': len(vy), 'tests': {}}
    for loss in (0, .1, .3):
        replay_started = time.perf_counter()
        rows, truth, ids = samples(sessions, 'test', loss)
        replay_elapsed = time.perf_counter() - replay_started
        started = time.perf_counter()
        p = model.predict_proba(matrix(rows))
        elapsed = time.perf_counter()-started
        predictions = [str(model.classes_[i]) if model.classes_[i] == 'BENIGN' or score >= threshold else 'UNCERTAIN'
                       for i, score in zip(p.argmax(axis=1), p.max(axis=1))]
        advisory_started = time.perf_counter()
        advisory = [detector.predict(row)['fragility'] for row in rows]
        advisory_elapsed = time.perf_counter() - advisory_started
        fragility_counts = {status: sum(a['status'] == status for a in advisory)
                            for status in ('sensitive', 'unchanged_in_tested_scenarios',
                                           'unavailable', 'not_applicable')}
        report['tests'][str(loss)] = {
            'fragility': {'status_counts': fragility_counts,
                          'sensitive_by_true_class': {
                              label: sum(a['status'] == 'sensitive' and actual == label
                                         for a, actual in zip(advisory, truth))
                              for label in sorted(set(truth))},
                          'full_detector_windows_per_second': len(rows) / max(advisory_elapsed, 1e-9),
                          'note': 'Advisory only; does not alter predictions or establish capture loss'},
            'ml': metrics(truth, predictions, rows, ids, sessions),
            'baseline': metrics(truth, [baseline(r['features']) for r in rows], rows, ids, sessions),
            'feature_replay_windows_per_second': len(rows)/max(replay_elapsed, 1e-9),
            'windows': len(rows), 'batch_inference_windows_per_second': len(rows)/max(elapsed, 1e-9)}
    report_path = output.with_suffix('.report.json')
    report_path.write_text(json.dumps(report, indent=2))
    return report_path
