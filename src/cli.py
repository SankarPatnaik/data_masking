
import argparse, json, os, sys
from src.masking_engine import Config, MaskingEngine

def main():
    parser = argparse.ArgumentParser(description="PII Masking CLI")
    parser.add_argument("--config", default=os.getenv("MASKING_CONFIG_PATH", "masking_config.yaml"))
    sub = parser.add_subparsers(dest="cmd")

    t = sub.add_parser("text", help="Mask a text string")
    t.add_argument("text", help="Input text string")

    j = sub.add_parser("json", help="Mask a JSON file")
    j.add_argument("path", help="Path to JSON file")

    args = parser.parse_args()
    cfg = Config.from_yaml(args.config)
    engine = MaskingEngine(cfg)

    if args.cmd == "text":
        res = engine.mask_text(args.text)
        print(json.dumps(res, ensure_ascii=False, indent=2))
    elif args.cmd == "json":
        with open(args.path, "r", encoding="utf-8") as f:
            payload = json.load(f)
        res = engine.mask_json(payload)
        print(json.dumps(res, ensure_ascii=False, indent=2))
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
