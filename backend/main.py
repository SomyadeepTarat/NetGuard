"""Run with python -m backend.main from the project root."""
import argparse
import math
import sys
import time
from backend.analyzer.traffic_analyzer import TrafficAnalyzer
from backend.capture.packet_capture import PacketCapture, list_interfaces, resolve_interface


def endpoint(address, port):
    return f"{address or '-'}:{port}" if port is not None else address or "-"


def render(stats, interface, status, clear=False):
    if clear:
        print("\033[2J\033[H", end="")
    print(f"NETGUARD — Real-Time Network Traffic Analyser\nStatus: {status} | Interface: {interface}")
    print(f"Total Packets: {stats['total_packets']:,} | Total Bytes: {stats['total_bytes']:,}")
    print(f"Average Packets/sec: {stats['packets_per_second']:.2f} | Average Bytes/sec: {stats['bytes_per_second']:.2f}")
    print(" | ".join(f"{key}: {value:,}" for key, value in stats['protocols'].items()))
    print(f"{'TIME':<9} {'SOURCE':<23} {'DESTINATION':<23} {'PROTOCOL':<8} {'BYTES':>6} FLAGS")
    for packet in stats['recent']:
        print(f"{packet.timestamp:%H:%M:%S}  {endpoint(packet.source_ip, packet.source_port):<23} "
              f"{endpoint(packet.destination_ip, packet.destination_port):<23} {packet.protocol:<8} "
              f"{packet.packet_size:>6} {', '.join(packet.tcp_flags) or '-'}")
    if 'ml' in stats:
        ml = stats['ml']
        print(f"ML scope: {ml['scope']} | Windows: {ml['windows']} | Queue drops: {ml['queue_drops']}")
        print("Scores are uncalibrated; predictions are not confirmed attacks.")
        for result in ml['recent'][-5:]:
            print(f"{result['source']} {result['decision']} {result['prediction']} "
                  f"score={result['score']:.3f} alert={result['alert']} evidence={result['evidence']}")
            fragility = result.get('fragility', {})
            if fragility.get('status') not in (None, 'not_applicable'):
                print(f"  Evidence fragility: {fragility['status']} | "
                      f"hypothetical pairs to change: {fragility.get('minimum_tested_pairs_to_change')} "
                      "(advisory)")
    print("Press Ctrl+C to stop" if status == "CAPTURING" else "Capture stopped", flush=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description="NetGuard v0.1 packet metadata monitor")
    parser.add_argument("--list-interfaces", action="store_true")
    parser.add_argument("--interface", help="Interface name; defaults to Scapy's route-selected interface")
    parser.add_argument("--pcap", help="Replay a PCAP file instead of live capture")
    parser.add_argument("--filter", help="Optional BPF capture filter (requires libpcap)")
    parser.add_argument("--refresh", type=float, default=1, help="Display interval in seconds (default: 1)")
    parser.add_argument('--model', help='Trusted locally trained NetGuard joblib model')
    parser.add_argument('--predictions', help='Write every ML window to JSONL (requires --model)')
    args = parser.parse_args(argv)
    if args.predictions and not args.model:
        parser.error('--predictions requires --model')
    if args.refresh <= 0 or not math.isfinite(args.refresh):
        parser.error("--refresh must be a finite positive number")
    if args.pcap and args.interface:
        parser.error("--pcap and --interface cannot be combined")
    if args.list_interfaces:
        for interface in list_interfaces():
            print(f"{interface.name}: {interface.description} ({interface.ip or 'no IPv4 address'})")
        return 0
    analyzer = TrafficAnalyzer()
    capture = None
    ml = None
    try:
        interface = args.pcap or resolve_interface(args.interface).name
        if args.model:
            from backend.ml.stream import StreamingAnalyzer
            ml = StreamingAnalyzer(analyzer, args.model, args.predictions, offline=bool(args.pcap))
            analyzer = ml
        capture = PacketCapture(analyzer, args.interface, args.pcap, args.filter)
        capture.start()
        print("NetGuard started", flush=True)
        while True:
            # Allow the capture worker to initialize and surface startup failures.
            time.sleep(args.refresh)
            running = capture.check()
            if not running:
                break
            render(analyzer.snapshot(), interface, "CAPTURING", sys.stdout.isatty())
    except KeyboardInterrupt:
        pass
    except Exception as error:
        print(f"Capture failed: {error}\nLive capture may require administrator privileges. See README.md.", file=sys.stderr)
        return 1
    finally:
        if capture is not None:
            try:
                capture.stop()
            except Exception:
                pass
        if ml is not None:
            try:
                ml.close()
            except Exception as error:
                print(f'ML failed: {error}', file=sys.stderr)
                return 1
    render(analyzer.snapshot(), locals().get("interface", "-"), "STOPPED", sys.stdout.isatty())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
