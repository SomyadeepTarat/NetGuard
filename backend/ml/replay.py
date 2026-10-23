"""Deterministic offline PCAP replay supporting controlled counterfactual perturbations.

Simulates packet observation loss without transmitting packets to any network.
Loss is injected in simulation; it does not measure or prove actual live packet loss.
"""
import random
from typing import Optional
from scapy.utils import PcapReader
from backend.analyzer.packet_parser import parse_packet
from backend.ml.features import FeatureExtractor


def replay(
    path,
    drop_rate: float = 0.0,
    seed: int = 0,
    loss_mode: str = 'random',  # 'random', 'burst', 'directional'
    burst_size: int = 4,
    burst_interval: int = 20,
    drop_ip: Optional[str] = None,
):
    """Replay an offline PCAP file through the canonical FeatureExtractor.
    
    Supports:
    - Baseline: drop_rate=0
    - Random Loss: seeded pseudo-random drop at rate in [0, 1)
    - Burst Loss: periodic omission of burst_size consecutive packets
    - Directional Loss: omission targeted to packets from drop_ip
    """
    if not 0 <= drop_rate < 1:
        raise ValueError('drop_rate must be in [0, 1)')
    if loss_mode not in ('random', 'burst', 'directional'):
        raise ValueError(f"Unknown loss_mode: {loss_mode}")

    extractor = FeatureExtractor()
    rng = random.Random(seed)
    packet_index = 0
    burst_remaining = 0

    with PcapReader(str(path)) as packets:
        for raw in packets:
            packet_index += 1
            parsed = parse_packet(raw)
            dropped = False

            if loss_mode == 'random':
                if drop_rate > 0 and rng.random() < drop_rate:
                    dropped = True
            elif loss_mode == 'burst':
                if drop_rate > 0:
                    if packet_index % burst_interval == 0:
                        burst_remaining = burst_size
                    if burst_remaining > 0:
                        burst_remaining -= 1
                        dropped = True
            elif loss_mode == 'directional':
                if drop_ip and parsed.source_ip == drop_ip:
                    if drop_rate > 0 and rng.random() < drop_rate:
                        dropped = True

            if dropped:
                continue

            for row in extractor.process(parsed):
                if drop_rate > 0:
                    row['quality']['injected_drop_rate'] = drop_rate
                    row['quality']['loss_mode'] = loss_mode
                    row['quality']['simulation_seed'] = seed
                yield row

    for row in extractor.finish():
        if drop_rate > 0:
            row['quality']['injected_drop_rate'] = drop_rate
            row['quality']['loss_mode'] = loss_mode
            row['quality']['simulation_seed'] = seed
        yield row
