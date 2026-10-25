"""Read documentation and Python syntax without importing audited code."""
import ast
from pathlib import Path
import re

PHRASES = {
    "no-eval": ["no eval", "never uses eval", "does not use eval", "doesn't use eval",
                "no exec(", "never executes code", "does not execute code", "no code execution",
                "no dynamic code execution", "never evals", "does not eval"],
    "no-shell": ["no shell", "never shells out", "does not shell out", "doesn't shell out",
                 "no subprocess", "never uses subprocess", "does not use subprocess",
                 "no shell commands", "never runs shell commands", "does not run shell commands",
                 "no system calls"],
    "no-pickle": ["no pickle", "never uses pickle", "does not use pickle", "doesn't use pickle",
                  "no unsafe deserialization", "never deserializes untrusted",
                  "does not deserialize untrusted", "no yaml.load", "never uses yaml.load"],
    "safe-input": ["safe on untrusted input", "safe to run on untrusted input",
                   "safe for untrusted input", "safe with untrusted input"],
}
EXCLUDED = {"tests", "fixtures", "docs"}

def files(root):
    """Walk regular files only, never following directory or file symlinks."""
    for item in sorted(root.iterdir()):
        if item.is_symlink():
            continue
        if item.is_dir():
            yield from files(item)
        elif item.is_file():
            yield item

def claims_in(text, file):
    fence = None
    for number, line in enumerate(text.splitlines(), 1):
        match = re.match(r"^\s{0,3}(`{3,}|~{3,})", line)
        if match:
            token = match.group(1)
            if fence is None:
                fence = token
            elif token[0] == fence[0] and len(token) >= len(fence):
                fence = None
            continue
        if fence:
            continue
        lower = line.lower()
        if any(x in lower for x in ("not enough", "not sufficient", "insufficient", "is not safe", "is unsafe", "avoid")):
            continue
        for kind, phrases in PHRASES.items():
            for phrase in phrases:
                boundary = r"(?!\w)" if phrase[-1].isalnum() else ""
                if not re.search(r"(?<!\w)" + re.escape(phrase) + boundary, lower):
                    continue
                if phrase == "no system calls" and not any(x in lower for x in ("shell", "command", "subprocess", "system(")):
                    continue
                yield {"kind": kind, "file": file, "line": number, "claim": line.strip()}
                break

def evidence_in(text):
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return []
    aliases = {}
    shadowed = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for name in node.names:
                aliases[name.asname or name.name.split('.')[0]] = name.name
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            for name in node.names:
                aliases[name.asname or name.name] = (node.module or '') + '.' + name.name
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            shadowed.add(node.name)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            shadowed.add(node.id)
        elif isinstance(node, ast.arg):
            shadowed.add(node.arg)
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = None
        if isinstance(func, ast.Name):
            if func.id in shadowed:
                continue
            name = aliases.get(func.id, func.id)
        elif isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            if func.value.id in shadowed:
                continue
            name = aliases.get(func.value.id, func.value.id) + '.' + func.attr
        if name is None:
            continue
        kind = None
        if name in {'eval', 'exec', 'compile'}:
            kind = 'eval'
        elif name == '__import__' and node.args and not isinstance(node.args[0], ast.Constant):
            kind = 'eval'
        elif (name.startswith('subprocess.') or name in {'os.system', 'os.popen', 'commands.getoutput', 'commands.getstatusoutput'} or name.startswith('os.spawn')):
            kind = 'shell'
        elif name in {'pickle.loads', 'pickle.load', 'pickle.Unpickler', 'marshal.loads', 'marshal.load', 'shelve.open', 'dill.loads', 'dill.load'}:
            kind = 'pickle'
        elif name == 'yaml.load' and not any(kw.arg == 'Loader' for kw in node.keywords):
            kind = 'pickle'
        if kind:
            found.append((kind, name + '('))
    return found

def audit(path='.', ignore=()):
    root = Path(path)
    if not root.is_dir():
        raise ValueError('audit path must be an existing readable directory')
    claims = []
    evidence = {'eval': [], 'shell': [], 'pickle': []}
    source_count = 0
    for file in files(root):
        relative = file.relative_to(root)
        if (file.name == 'README.md' and len(relative.parts) == 1) or (relative.parts[0] == 'docs' and file.suffix == '.md'):
            claims.extend(claims_in(file.read_text(encoding='utf-8', errors='replace'), relative.as_posix()))
        if file.suffix != '.py':
            continue
        source_count += 1
        test_only = bool(set(relative.parts[:-1]) & EXCLUDED) or file.name.startswith('test_') or file.name.endswith('_test.py')
        for kind, pattern in evidence_in(file.read_text(encoding='utf-8', errors='replace')):
            evidence[kind].append((test_only, pattern))
    findings, verified = [], []
    for claim in claims:
        kind = 'eval' if claim['kind'] == 'safe-input' else claim['kind'][3:]
        matches = evidence[kind]
        public = {key: value for key, value in claim.items() if key != 'kind'}
        if matches or not source_count:
            production = not source_count or any(not match[0] for match in matches)
            suffix = 'false' if production else 'test-only'
            rule = 'documented-' + claim['kind'] + '-claim-' + suffix
            if rule in ignore:
                continue
            pattern = next((pattern for test, pattern in matches if not test), matches[0][1] if matches else 'no Python source')
            findings.append(dict(public, rule=rule, severity='HIGH' if production else 'MEDIUM', evidence=pattern))
        else:
            verified.append(public)
    return {'findings': findings, 'verified_claims': verified,
            'summary': {'claims': len(claims), 'findings': len(findings), 'verified': len(verified), 'python_files': source_count}}
