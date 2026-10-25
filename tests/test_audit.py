import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from security_claim_audit.audit import audit, claims_in, evidence_in, PHRASES
from security_claim_audit.cli import main

FIXTURES = Path(__file__).parent / 'fixtures'

class AuditTests(unittest.TestCase):
    def project(self, claim='No eval', code='eval(value)', source='app.py'):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        (root / 'README.md').write_text(claim)
        if code is not None:
            file = root / source
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text(code)
        return root

    def cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            status = main([str(a) for a in args])
        return status, out.getvalue(), err.getvalue()

    def test_good(self):
        result = audit(FIXTURES / 'good')
        self.assertEqual(result['findings'], [])
        self.assertEqual(len(result['verified_claims']), 4)

    def test_bad(self):
        result = audit(FIXTURES / 'bad')
        self.assertEqual({f['rule'] for f in result['findings']}, {'documented-' + k + '-claim-false' for k in PHRASES})
        self.assertEqual(len(result['findings']), 4)
        self.assertTrue(all(f['severity'] == 'HIGH' for f in result['findings']))

    def test_inline_exec_claim(self):
        self.assertEqual(len(list(claims_in('We promise `no exec(code)`.', 'README.md'))), 1)

    def test_inline_eval_claim(self):
        self.assertEqual(len(list(claims_in('We promise `no eval(input)`.', 'README.md'))), 1)

    def test_system_command_context(self):
        self.assertEqual(len(list(claims_in('No system calls for shell commands', 'README.md'))), 1)

    def test_no_claims(self):
        self.assertFalse(audit(self.project('Ordinary tool'))['findings'])

    def test_no_source(self):
        self.assertEqual(len(audit(self.project(code=None))['findings']), 1)

    def test_invalid_source_skipped(self):
        self.assertFalse(audit(self.project(code='invalid syntax !'))['findings'])

    def test_ignore(self):
        self.assertFalse(audit(self.project(), ['documented-no-eval-claim-false'])['findings'])

    def test_production_wins(self):
        root = self.project(source='tests/test_app.py')
        (root / 'prod.py').write_text('exec(x)')
        self.assertEqual(audit(root)['findings'][0]['severity'], 'HIGH')

    def test_docs_claim(self):
        root = self.project('nothing')
        (root / 'docs/nested').mkdir(parents=True)
        (root / 'docs/nested/guide.md').write_text('No eval')
        self.assertEqual(audit(root)['findings'][0]['file'], 'docs/nested/guide.md')

    def test_other_markdown_ignored(self):
        root = self.project('nothing')
        (root / 'OTHER.md').write_text('No eval')
        self.assertFalse(audit(root)['findings'])

    def test_symlink_source(self):
        root = self.project(code='pass')
        (root / 'link.py').symlink_to(FIXTURES.absolute() / 'bad/app.py')
        self.assertFalse(audit(root)['findings'])

    def test_symlink_docs(self):
        root = self.project('nothing')
        (root / 'docs').symlink_to(FIXTURES.absolute() / 'bad', target_is_directory=True)
        self.assertFalse(audit(root)['findings'])

    def test_never_open_env(self):
        original = Path.open
        def guarded(path, *args, **kwargs):
            self.assertNotEqual(path.name, '.env')
            return original(path, *args, **kwargs)
        with patch.object(Path, 'open', guarded):
            for flags in [[], ['--json'], ['--verbose']]:
                status, out, err = self.cli(FIXTURES / 'bad', *flags)
                self.assertEqual(status, 2)
                self.assertNotIn('SECURITY_AUDIT_NEVER_READ_MARKER_729451', out + err)

    def test_json(self):
        status, out, _ = self.cli(FIXTURES / 'bad', '--json')
        self.assertEqual(status, 2)
        self.assertEqual(set(json.loads(out)), {'findings', 'verified_claims', 'summary'})

    def test_verbose(self):
        status, out, _ = self.cli(FIXTURES / 'good', '--verbose')
        self.assertEqual(status, 0)
        self.assertEqual(out.count('VERIFIED'), 4)

    def test_cli_ignore(self):
        status, _, _ = self.cli(self.project(), '--ignore', 'documented-no-eval-claim-false')
        self.assertEqual(status, 0)

    def test_threshold(self):
        root = self.project(source='tests/sample.py')
        status, out, _ = self.cli(root, '--fail-on', 'HIGH')
        self.assertEqual(status, 0)
        self.assertIn('MEDIUM', out)
        self.assertEqual(self.cli(root)[0], 2)

    def test_missing(self):
        self.assertEqual(self.cli('/path/does/not/exist')[0], 1)

    def test_file_root(self):
        self.assertEqual(self.cli(FIXTURES / 'bad/app.py')[0], 1)

    def test_unreadable(self):
        with patch.object(Path, 'iterdir', side_effect=PermissionError('unreadable')):
            self.assertEqual(self.cli(FIXTURES / 'good')[0], 1)

    def test_usage(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as cm:
            main(['--fail-on', 'LOW'])
        self.assertEqual(cm.exception.code, 1)

    def test_version(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as cm:
            main(['--version'])
        self.assertEqual(cm.exception.code, 0)
        self.assertEqual(out.getvalue().strip(), '0.1.0')

    def test_default_path(self):
        with patch('security_claim_audit.cli.audit', return_value={'findings': [], 'verified_claims': []}) as call:
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main([]), 0)
            call.assert_called_once_with('.', set())

    def test_safe_input_shell_alone(self):
        self.assertFalse(audit(self.project('Safe for untrusted input', 'subprocess.run(x)'))['findings'])

    def test_safe_input_pickle_alone(self):
        self.assertFalse(audit(self.project('Safe for untrusted input', 'pickle.loads(x)'))['findings'])

    def test_line_number(self):
        finding = audit(self.project('\nNo eval'))['findings'][0]
        self.assertEqual(finding['line'], 2)
        self.assertEqual(finding['evidence'], 'eval(')


def add_case(name, function):
    setattr(AuditTests, 'test_' + name, function)

for kind, phrases in PHRASES.items():
    for index, phrase in enumerate(phrases):
        def check(self, kind=kind, phrase=phrase):
            self.assertEqual(list(claims_in(phrase.upper(), 'README.md'))[0]['kind'], kind)
        if phrase != 'no system calls':
            add_case('phrase_' + kind.replace('-', '_') + '_' + str(index), check)

positive = [
    ('eval(x)', 'eval'), ('exec(x)', 'eval'), ('compile(x,"x","exec")', 'eval'),
    ('__import__(name)', 'eval'), ('subprocess.run(["ls"], shell=False)', 'shell'),
    ('from subprocess import run as sh\nsh(x)', 'shell'),
    ('import subprocess as sp\nsp.Popen(x)', 'shell'),
    ('os.system(x)', 'shell'), ('os.popen(x)', 'shell'), ('os.spawnv(x)', 'shell'),
    ('commands.getoutput(x)', 'shell'), ('commands.getstatusoutput(x)', 'shell'),
    ('import pickle as pk\npk.loads(x)', 'pickle'),
    ('from pickle import load as ld\nld(x)', 'pickle'),
    ('pickle.Unpickler(x)', 'pickle'), ('marshal.loads(x)', 'pickle'),
    ('marshal.load(x)', 'pickle'), ('shelve.open(x)', 'pickle'),
    ('dill.loads(x)', 'pickle'), ('dill.load(x)', 'pickle'), ('yaml.load(x)', 'pickle'),
]
for index, (code, kind) in enumerate(positive):
    def check(self, code=code, kind=kind):
        self.assertEqual(evidence_in(code)[0][0], kind)
    add_case('evidence_' + str(index), check)

negative = ['ast.literal_eval(x)', 'yaml.safe_load(x)', 'yaml.load(x, Loader=SafeLoader)',
            'yaml.load(x, Loader=yaml.SafeLoader)', '__import__("os")',
            'def eval(x):\n return x\neval(x)', 'eval = custom\neval(x)',
            'def exec(x):\n return x\nexec(x)', 'compile = custom\ncompile(x)',
            '"eval(x)"', '# eval(x)', 'invalid ! syntax']
for index, code in enumerate(negative):
    def check(self, code=code):
        self.assertEqual(evidence_in(code), [])
    add_case('negative_' + str(index), check)

for index, text in enumerate(['```\nNo eval\n```', '~~~python\nNo eval\n~~~',
    'No eval is not enough', 'No eval is not sufficient', 'No eval is insufficient',
    'This is not safe: no eval', 'This is unsafe: no eval', 'Avoid claiming no eval',
    'No system calls', 'There is no evaluation here']):
    def check(self, text=text):
        self.assertEqual(list(claims_in(text, 'README.md')), [])
    add_case('prose_negative_' + str(index), check)

for index, (claim, code) in enumerate([('No eval', 'eval(x)'), ('No shell', 'os.system(x)'),
    ('No pickle', 'pickle.loads(x)'), ('Safe for untrusted input', 'exec(x)')]):
    for location in ['tests/app.py', 'fixtures/app.py', 'docs/app.py', 'test_app.py', 'app_test.py']:
        def check(self, claim=claim, code=code, location=location):
            finding = audit(self.project(claim, code, location))['findings'][0]
            self.assertEqual(finding['severity'], 'MEDIUM')
            self.assertTrue(finding['rule'].endswith('test-only'))
        add_case('test_only_' + str(index) + '_' + location.replace('/', '_').replace('.', '_'), check)

if __name__ == '__main__':
    unittest.main()
