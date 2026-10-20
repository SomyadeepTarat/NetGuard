import argparse
import json
from backend.ml.demo import generate
from backend.ml.train import train
from backend.ml.replay import replay
from backend.ml.detector import Detector, JsonOutput


def main():
    parser = argparse.ArgumentParser(description='NetGuard ML: offline training and streaming PCAP predictions')
    commands = parser.add_subparsers(dest='command', required=True)
    demo = commands.add_parser('demo-data')
    demo.add_argument('--directory', default='artifacts/demo')
    demo.add_argument('--sessions', type=int, default=8)
    fit = commands.add_parser('train')
    fit.add_argument('--manifest', required=True)
    fit.add_argument('--model', default='artifacts/netguard.joblib')
    predict = commands.add_parser('predict')
    predict.add_argument('--pcap', required=True)
    predict.add_argument('--model', default='artifacts/netguard.joblib')
    predict.add_argument('--output')
    predict.add_argument('--drop-rate', type=float, default=0)
    args = parser.parse_args()
    if args.command == 'demo-data':
        if args.sessions < 1:
            parser.error('--sessions must be positive')
        print(generate(args.directory, args.sessions))
    elif args.command == 'train':
        print(train(args.manifest, args.model))
    else:
        detector = Detector(args.model)
        output = JsonOutput(args.output) if args.output else None
        try:
            for row in replay(args.pcap, args.drop_rate):
                result = detector.predict(row)
                if output:
                    output.emit(result)
                print(json.dumps(result))
        finally:
            if output:
                output.close()


if __name__ == '__main__':
    main()
