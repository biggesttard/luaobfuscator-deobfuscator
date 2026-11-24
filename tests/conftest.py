import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES = os.path.join(ROOT, 'tests', 'fixtures')

if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


@pytest.fixture(scope='session')
def fixtures_dir():
    return FIXTURES


@pytest.fixture(scope='session')
def spec():
    with open(os.path.join(FIXTURES, 'fixture.json'), encoding='utf-8') as fh:
        return json.load(fh)


@pytest.fixture(scope='session')
def golden():
    with open(os.path.join(FIXTURES, 'golden.json'), encoding='utf-8') as fh:
        return json.load(fh)


@pytest.fixture(scope='session')
def sample_source():
    with open(os.path.join(FIXTURES, 'sample_evil.lua'), encoding='latin-1') as fh:
        return fh.read()


@pytest.fixture(scope='session')
def sample_golden():
    with open(os.path.join(FIXTURES, 'sample_evil.golden.json'), encoding='utf-8') as fh:
        return json.load(fh)
