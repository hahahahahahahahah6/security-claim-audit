"""Console interface."""
import argparse
import json
import sys
from . import __version__
from .audit import audit

class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(1, self.prog + ": error: " + message + "\n")

def main(argv=None):
    parser = Parser(prog="security-claim-audit")
    parser.add_argument("path", nargs="?", default=".")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--fail-on", choices=["HIGH", "MEDIUM"], default="MEDIUM")
    parser.add_argument("--ignore", default="", metavar="RULE,...")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args(argv)
    try:
        result = audit(args.path, {s.strip() for s in args.ignore.split(",") if s.strip()})
    except (OSError, ValueError) as exc:
        print("security-claim-audit: " + str(exc), file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(result, ensure_ascii=True))
    else:
        for finding in result["findings"]:
            print('{severity} {rule} {file}:{line} claim={claim} evidence={evidence}'.format(
                **dict(finding, claim=json.dumps(finding['claim']), evidence=json.dumps(finding['evidence']))))
        if args.verbose:
            for claim in result["verified_claims"]:
                print('VERIFIED {file}:{line} claim={claim}'.format(**dict(claim, claim=json.dumps(claim['claim']))))
        print("FAIL" if any(f['severity'] == 'HIGH' or args.fail_on == 'MEDIUM' for f in result['findings']) else "PASS")
    return 2 if any(f['severity'] == 'HIGH' or args.fail_on == 'MEDIUM' for f in result['findings']) else 0
