"""Advisory sensitivity analysis, never packet reconstruction or a loss estimate."""
from backend.ml.features import FEATURES


def handshake_fragility(model, row, threshold, max_pairs=32):
    """Enumerate 1..32 missing SYN+ACK/ACK pairs; no monotonicity assumption.

    Both hypothetical packets are 54 bytes and lie within the observed time
    span. This is one restricted scenario family, not a robustness certificate.
    """
    result = {'method': 'missing-handshake-pairs-v1', 'advisory_only': True,
              'status': 'unavailable', 'tested_scenarios': 0,
              'minimum_tested_pairs_to_change': None,
              'assumptions': '54-byte SYN+ACK and ACK pairs within observed span; no new SYNs',
              'capture_loss_estimate': None}
    context = row.get('handshake_context')
    if not context:
        result['reason'] = 'Handshake context absent; replay with the current extractor'
        return result
    if any(row['quality'].get(k, 0) for k in ('state_evictions', 'late_packets', 'queue_drops')):
        result['reason'] = 'Recorded observation state loss'
        return result
    count = min(context['repairable_flows'], max_pairs)
    if not count:
        result['reason'] = 'No eligible incomplete SYN flows'
        return result
    original = row['features']
    n = original['packets']
    scenarios = []
    for pairs in range(1, count + 1):
        features = original.copy()
        total = n + 2 * pairs
        byte_sum = original['mean_size'] * n + 108 * pairs
        features.update(
            packets=total,
            bytes_per_second=byte_sum / context['window_seconds'],
            mean_size=byte_sum / total,
            response_fraction=(original['response_fraction'] * n + pairs) / total,
            completed_fraction=(context['completed_flows'] + pairs) / context['syn_flows'],
            mean_gap=original['mean_gap'] * max(n - 1, 1) / (total - 1))
        for name in ('rst_fraction', 'udp_fraction', 'icmp_fraction'):
            features[name] = original[name] * n / total
        scenarios.append(features)
    probabilities = model.predict_proba([[f[name] for name in FEATURES] for f in scenarios])
    result.update(status='unchanged_in_tested_scenarios', tested_scenarios=count,
                  search_truncated=context['repairable_flows'] > count)
    for pairs, scores in enumerate(probabilities, 1):
        index = scores.argmax()
        label, score = str(model.classes_[index]), float(scores[index])
        if label != 'SYN_FLOOD' or score < threshold:
            result.update(status='sensitive', minimum_tested_pairs_to_change=pairs,
                          hypothetical_packets=2 * pairs,
                          hypothetical_missing_fraction=2 * pairs / (n + 2 * pairs),
                          alternative_prediction=label, alternative_score=score,
                          alternative_decision='BENIGN' if label == 'BENIGN' else
                          ('SUSPECTED' if score >= threshold else 'UNCERTAIN'))
            break
    return result
