"""Shared non-tree estimators and preprocessing for training and evaluation."""
import numpy as np
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, RobustScaler
from sklearn.svm import SVC
from sklearn.neighbors import LocalOutlierFactor
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import StratifiedGroupKFold

CLASSIFIER_ALGORITHM = 'calibrated-rbf-svm-v1'
ANOMALY_ALGORITHM = 'novelty-lof-v1'


def preprocessing():
    return [('log', FunctionTransformer(np.log1p, validate=True)),
            ('scale', RobustScaler())]


def build_classifier(cv=3):
    # Scores support the existing evidence interface. Internal probability
    # estimates are not independently validated probabilities of attack intent.
    estimator = Pipeline(preprocessing() + [('classifier', SVC(
        C=10.0, kernel='rbf', gamma='scale', class_weight='balanced',
        random_state=42, cache_size=128))])
    # Each calibration fold refits its own preprocessing and SVM. Production
    # training supplies capture-grouped folds; feature fixtures use three folds.
    return CalibratedClassifierCV(estimator, method='sigmoid', cv=cv, ensemble=False, n_jobs=1)


def session_calibration_folds(X, labels, groups):
    counts = min(len({sid for sid, label in zip(groups, labels) if label == category}) for category in set(labels))
    if counts < 2:
        raise ValueError('SVM calibration requires at least two independent training sessions per class')
    folds = list(StratifiedGroupKFold(n_splits=min(3, counts), shuffle=True, random_state=42).split(X, labels, groups))
    for train, _ in folds:
        if {labels[i] for i in train} != set(labels):
            raise ValueError('Calibration fold is missing a class; supply more independent training sessions')
    return folds


def build_novelty_detector(sample_count, contamination=.05):
    if sample_count < 2:
        raise ValueError('Novelty LOF needs at least two reference samples')
    return Pipeline(preprocessing() + [('novelty', LocalOutlierFactor(
        n_neighbors=min(20, sample_count - 1), novelty=True,
        contamination=contamination, n_jobs=1))])


def is_supported_classifier(model):
    return (isinstance(model, CalibratedClassifierCV) and isinstance(model.estimator, Pipeline)
            and isinstance(model.estimator.named_steps.get('classifier'), SVC))
