import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLE = os.path.join(ROOT, 'tests', 'fixtures', 'sample_evil.lua')


def run_cli(args, cwd):
    env = dict(os.environ)
    env['PYTHONPATH'] = ROOT + os.pathsep + env.get('PYTHONPATH', '')
    return subprocess.run([sys.executable, '-m', 'deobf'] + args,
                          cwd=cwd, env=env, capture_output=True, text=True)


def test_help_exits_zero():
    res = run_cli(['--help'], ROOT)
    assert res.returncode == 0
    assert 'deobf <file.lua>' in res.stderr


def test_no_arguments_exits_one():
    res = run_cli([], ROOT)
    assert res.returncode == 1
    assert 'usage' in res.stderr.lower() or '<file.lua>' in res.stderr


def test_json_output_to_file(tmp_path, sample_golden):
    dest = tmp_path / 'out.json'
    res = run_cli([SAMPLE, '--json', '--out', str(dest)], tmp_path)
    assert res.returncode == 0, res.stderr

    data = json.loads(dest.read_text(encoding='utf-8'))
    assert set(data) == {'detection', 'vm', 'lua', 'disasm'}
    assert data['lua'] == sample_golden['lua']
    assert data['vm']['opcodeCount'] == sample_golden['vm']['opcodeCount']


def test_default_output_path(tmp_path, sample_golden):
    res = run_cli([SAMPLE], tmp_path)
    assert res.returncode == 0, res.stderr
    dest = tmp_path / 'output' / os.path.basename(SAMPLE) / 'deobfuscated.lua'
    assert dest.is_file()
    assert dest.read_text(encoding='utf-8') == sample_golden['lua']
    assert 'lines=' in res.stderr


def test_stdout_and_disasm(tmp_path):
    res = run_cli([SAMPLE, '--stdout', '--disasm', '--out', str(tmp_path / 'a.lua')], tmp_path)
    assert res.returncode == 0, res.stderr
    assert '.proto main' in res.stdout
    assert 'return main()' in res.stdout


def test_rejects_unrelated_file(tmp_path):
    bad = tmp_path / 'plain.lua'
    bad.write_text('print("hello")\n', encoding='utf-8')
    res = run_cli([str(bad)], tmp_path)
    assert res.returncode == 1
    assert '[err]' in res.stderr
