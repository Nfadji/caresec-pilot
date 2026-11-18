from pathlib import Path
import csv, json, argparse, hashlib

ROOT = Path(__file__).resolve().parents[1]
CONDITIONS = {'A':'Complete', 'B':'Masked', 'C':'Disagreement', 'D':'Provenance Gap'}

def build(manifest, scanner_file=None):
    with manifest.open(encoding='utf-8-sig', newline='') as f:
        cases = list(csv.DictReader(f))
    if len(cases) != 20 or len({c['case_id'] for c in cases}) != 20:
        raise ValueError('Expected exactly 20 unique cases')
    scans = {}
    if scanner_file:
        raw = json.loads(scanner_file.read_text(encoding='utf-8'))
        if not isinstance(raw, dict):
            raise ValueError('Scanner JSON must be an object keyed by case_id')
        scans = raw
    output = []
    for case in cases:
        case_id = case['case_id']
        source = ROOT / case['source_path']
        if not source.is_file():
            raise FileNotFoundError(source)
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        if digest != case['file_hash']:
            print(f'WARNING: SHA-256 differs from manifest for {case_id}; check line endings or dataset version')
        evidence = scans.get(case_id, {})
        if not isinstance(evidence, dict):
            raise ValueError(f'Scanner evidence must be an object: {case_id}')
        for condition, label in CONDITIONS.items():
            record = {
                'record_id': f'{case_id}_{condition}',
                'case_id': case_id,
                'condition': condition,
                'condition_name': label,
                'CWE': case['CWE'],
                'source_path': case['source_path'],
                'line_range': case['line_range'],
                'evidence': dict(evidence),
                'variant_status': 'ready',
            }
            if condition == 'B':
                record['evidence'] = {}
                record['masked_fields'] = sorted(evidence)
                record['variant_status'] = 'ready' if evidence else 'awaiting_scanner_evidence'
            elif condition == 'C':
                outcomes = [v.get('status') for v in evidence.values() if isinstance(v, dict) and v.get('status') in ('finding', 'no_finding')]
                if 'finding' not in outcomes or 'no_finding' not in outcomes:
                    record['variant_status'] = 'awaiting_verified_disagreement'
                else:
                    record['variant_status'] = 'ready'
            elif condition == 'D':
                record['evidence'] = {k: {field: value for field, value in v.items() if field not in ('source', 'source_url', 'provenance', 'tool_version', 'rule_id')} if isinstance(v, dict) else v for k,v in evidence.items()}
                record['removed_provenance_fields'] = ['source', 'source_url', 'provenance', 'tool_version', 'rule_id']
                record['variant_status'] = 'ready' if evidence else 'awaiting_scanner_evidence'
            elif not evidence:
                record['variant_status'] = 'awaiting_scanner_evidence'
            output.append(record)
    return output

def main():
    parser = argparse.ArgumentParser(description='CARE-Sec Lane 2 provisional evidence variants')
    parser.add_argument('--scanner-json', type=Path, help='Optional JSON object keyed by case_id with scanner evidence')
    parser.add_argument('--output', type=Path, default=ROOT/'variants'/'variants_preview.json')
    args = parser.parse_args()
    records = build(ROOT/'manifests'/'case_manifest_public.csv', args.scanner_json)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(records, indent=2) + '\n', encoding='utf-8')
    print(f'Wrote {len(records)} records to {args.output}')
    from collections import Counter
    print('Statuses:', dict(Counter(r['variant_status'] for r in records)))
    print('NOTE: Provisional schema; obtain frozen schema and scanner ledger before integration.')

if __name__ == '__main__':
    main()
