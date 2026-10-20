import json
from pathlib import Path
import joblib
from backend.ml.features import FEATURES, SCHEMA
from backend.ml.fragility import handshake_fragility


def baseline(features):
    if features['unique_ports'] >= 15 and features['syn_rate'] >= 2:
        return 'PORT_SCAN'
    if features['syn_rate'] >= 30 and features['completed_fraction'] < .1:
        return 'SYN_FLOOD'
    if features['bytes_per_second'] >= 80000:
        return 'TRAFFIC_FLOOD'
    return 'BENIGN'


class Detector:
    def __init__(self, model_path, threshold=None):
        # joblib uses pickle: load only models created locally or from trusted sources.
        self.bundle = joblib.load(model_path)
        if self.bundle['schema'] != SCHEMA or self.bundle['features'] != FEATURES:
            raise ValueError('Model feature schema mismatch; retrain the model')
        self.threshold = self.bundle['threshold'] if threshold is None else threshold
        if not 0 <= self.threshold <= 1:
            raise ValueError('Threshold must be between zero and one')

    def predict(self, row):
        model = self.bundle['model']
        probabilities = model.predict_proba([[row['features'][f] for f in FEATURES]])[0]
        index = probabilities.argmax()
        label, score = str(model.classes_[index]), float(probabilities[index])
        rule = baseline(row['features'])
        decision = 'BENIGN' if label == 'BENIGN' else ('SUSPECTED' if score >= self.threshold else 'UNCERTAIN')
        if row['quality']['state_evictions'] or row['quality']['late_packets']:
            decision = 'UNCERTAIN' if label != 'BENIGN' else 'BENIGN'
        fragility = (handshake_fragility(model, row, self.threshold)
                     if label == 'SYN_FLOOD' and score >= self.threshold else
                     {'status': 'not_applicable', 'advisory_only': True,
                      'reason': 'Requires a SYN_FLOOD prediction above the score threshold'})
        return {**row, 'prediction': label, 'score': score, 'decision': decision,
                'fragility': fragility,
                'baseline': rule, 'corroborated': rule == label and label != 'BENIGN',
                'model_scope': self.bundle['scope'],
                'evidence': {k: round(row['features'][k], 4) for k in
                             ('syn_rate', 'unique_ports', 'completed_fraction', 'bytes_per_second', 'response_fraction')}}


class JsonOutput:
    def __init__(self, path):
        self.file = Path(path).open('w')

    def emit(self, record):
        self.file.write(json.dumps(record) + '\n')
        self.file.flush()

    def close(self):
        self.file.close()
