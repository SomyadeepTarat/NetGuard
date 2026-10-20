import random
from scapy.utils import PcapReader
from backend.analyzer.packet_parser import parse_packet
from backend.ml.features import FeatureExtractor


def replay(path, drop_rate=0, seed=0):
    if not 0 <= drop_rate < 1:
        raise ValueError('drop_rate must be in [0, 1)')
    extractor = FeatureExtractor()
    rng = random.Random(seed)
    with PcapReader(str(path)) as packets:
        for raw in packets:
            if rng.random() < drop_rate:
                continue
            for row in extractor.process(parse_packet(raw)):
                if drop_rate:
                    row['quality']['injected_drop_rate'] = drop_rate
                yield row
    for row in extractor.finish():
        if drop_rate:
            row['quality']['injected_drop_rate'] = drop_rate
        yield row
