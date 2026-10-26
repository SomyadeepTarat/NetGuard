"""Passive adapter checks and explicit offline dataset selection (no ping/probe)."""
from ipaddress import ip_address
from pathlib import Path
import os

import psutil

from backend.capture.packet_capture import list_interfaces, resolve_interface
from backend.services.pcap_resolver import resolve_safe_pcap_path


def connected_interface(name=None):
    stats, addresses = psutil.net_if_stats(), psutil.net_if_addrs()
    preferred = resolve_interface(name)
    candidates = [preferred] if name else [preferred] + list_interfaces()
    for iface in candidates:
        identifiers = {str(getattr(iface, key, '')).lower() for key in ('name', 'description', 'network_name')}
        iface_ips = set(str(value) for value in getattr(iface, 'ips', {}).get(4, []))
        iface_ips.add(str(getattr(iface, 'ip', '')))
        for adapter, status in stats.items():
            adapter_addresses = addresses.get(adapter, [])
            matches = adapter.lower() in identifiers or any(a.address in iface_ips for a in adapter_addresses)
            if not matches or not status.isup:
                continue
            for address in adapter_addresses:
                try:
                    ip = ip_address(address.address.split('%')[0])
                    if not (ip.is_loopback or ip.is_unspecified or ip.is_link_local or ip.is_multicast):
                        return iface
                except ValueError:
                    continue
    raise RuntimeError('No active non-loopback capture adapter with a usable IP address')


def select_dataset(artifacts_dir, requested=None):
    """Never silently substitute generated synthetic data for a real dataset."""
    requested = requested or os.environ.get('NETGUARD_DATASET_PCAP')
    if requested:
        return resolve_safe_pcap_path(requested, additional_roots=[Path(artifacts_dir)])
    roots = [Path(artifacts_dir) / 'datasets', Path(artifacts_dir)]
    for root in roots:
        if root.exists():
            files = sorted(p for p in root.iterdir() if p.is_file() and p.suffix.lower() in ('.pcap', '.pcapng', '.cap'))
            if files:
                return resolve_safe_pcap_path(str(files[0]), additional_roots=[Path(artifacts_dir)])
    return None
