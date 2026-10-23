"""Deterministic offline PCAP replay supporting controlled counterfactual perturbations.

Simulates packet observation loss without transmitting packets to any network.
Loss is injected in simulation; it does not measure or prove actual live packet loss.
Includes accurate packet omission accounting (realized vs nominal rates).
"""
from dataclasses import dataclass, field
import random
from typing import Iterator, Optional
from scapy.utils import PcapReader
from backend.analyzer.packet_parser import parse_packet
from backend.ml.features import FeatureExtractor


@dataclass
class ReplayTelemetry:
    """Accurate packet accounting for offline replay experiments."""
    source_packets: int = 0
    eligible_packets: int = 0
    omitted_packets: int = 0
    retained_packets: int = 0
    realized_omission_rate: float = 0.0
    eligible_omission_rate: float = 0.0
    loss_mode: str = "random"
    nominal_drop_rate: float = 0.0
    seed: int = 0
    burst_size: int = 4
    burst_interval: int = 20
    drop_ip: Optional[str] = None

    def finalize(self) -> None:
        if self.source_packets > 0:
            self.realized_omission_rate = round(self.omitted_packets / self.source_packets, 6)
        else:
            self.realized_omission_rate = 0.0
            
        if self.eligible_packets > 0:
            self.eligible_omission_rate = round(self.omitted_packets / self.eligible_packets, 6)
        else:
            self.eligible_omission_rate = 0.0


def replay_stream(
    path,
    drop_rate: float = 0.0,
    seed: int = 0,
    loss_mode: str = 'random',  # 'random', 'burst', 'directional'
    burst_size: int = 4,
    burst_interval: int = 20,
    drop_ip: Optional[str] = None,
    telemetry: Optional[ReplayTelemetry] = None,
) -> Iterator[dict]:
    """Replay an offline PCAP file through the canonical FeatureExtractor with packet telemetry.
    
    Supports:
    - Baseline: drop_rate=0
    - Random Loss: seeded pseudo-random drop at rate in [0, 1)
    - Burst Loss: periodic omission of burst_size consecutive packets every burst_interval
    - Directional Loss: omission targeted to packets from drop_ip
    """
    if not 0 <= drop_rate < 1:
        raise ValueError('drop_rate must be in [0, 1)')
    if loss_mode not in ('random', 'burst', 'directional'):
        raise ValueError(f"Unknown loss_mode: {loss_mode}")
    if burst_size < 1:
        raise ValueError("burst_size must be at least 1")
    if burst_interval < 1:
        raise ValueError("burst_interval must be at least 1")

    if telemetry is not None:
        telemetry.loss_mode = loss_mode
        telemetry.nominal_drop_rate = drop_rate
        telemetry.seed = seed
        telemetry.burst_size = burst_size
        telemetry.burst_interval = burst_interval
        telemetry.drop_ip = drop_ip

    extractor = FeatureExtractor()
    rng = random.Random(seed)
    packet_index = 0
    burst_remaining = 0

    with PcapReader(str(path)) as packets:
        for raw in packets:
            packet_index += 1
            if telemetry is not None:
                telemetry.source_packets += 1

            parsed = parse_packet(raw)
            dropped = False
            is_eligible = True

            if loss_mode == 'random':
                is_eligible = True
                if drop_rate > 0 and rng.random() < drop_rate:
                    dropped = True
            elif loss_mode == 'burst':
                is_eligible = True
                if drop_rate > 0:
                    if packet_index % burst_interval == 0:
                        burst_remaining = burst_size
                    if burst_remaining > 0:
                        burst_remaining -= 1
                        dropped = True
            elif loss_mode == 'directional':
                is_eligible = bool(drop_ip and parsed.source_ip == drop_ip)
                if is_eligible:
                    if drop_rate > 0 and rng.random() < drop_rate:
                        dropped = True

            if telemetry is not None:
                if is_eligible:
                    telemetry.eligible_packets += 1
                if dropped:
                    telemetry.omitted_packets += 1
                else:
                    telemetry.retained_packets += 1

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

    if telemetry is not None:
        telemetry.finalize()


def get_window_key(row: dict) -> str:
    """Computes a deterministic, stable key for aligning rolling windows across runs."""
    return f"{row.get('source', '-') }@{round(float(row.get('timestamp', 0.0)), 3)}"


def replay(
    path,
    drop_rate: float = 0.0,
    seed: int = 0,
    loss_mode: str = 'random',
    burst_size: int = 4,
    burst_interval: int = 20,
    drop_ip: Optional[str] = None,
):
    """Backwards-compatible replay generator preserving the exact original signature."""
    yield from replay_stream(
        path=path,
        drop_rate=drop_rate,
        seed=seed,
        loss_mode=loss_mode,
        burst_size=burst_size,
        burst_interval=burst_interval,
        drop_ip=drop_ip,
        telemetry=None,
    )
