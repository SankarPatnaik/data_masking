import argparse
import json
import os
import sys

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
        # Determine if file is JSON array, single object, or JSON Lines
        with open(args.path, "r", encoding="utf-8") as f:
            content = f.read()

        stripped = content.strip()
        records = []
        if stripped.startswith("[") and stripped.endswith("]"):
            try:
                records = json.loads(stripped)
            except json.JSONDecodeError:
                print("Invalid JSON array", file=sys.stderr)
                sys.exit(1)
        else:
            try:
                records = [json.loads(stripped)]
            except json.JSONDecodeError:
                # Treat as JSON Lines
                for line in content.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    records.append(json.loads(line))

        # Apply masking to each record
        masked = [engine.mask_json(rec) for rec in records]

        # Return list if multiple records, else single object
        if len(masked) == 1:
            print(json.dumps(masked[0], ensure_ascii=False, indent=2))
        else:
            print(json.dumps(masked, ensure_ascii=False, indent=2))
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
