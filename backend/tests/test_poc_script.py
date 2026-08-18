from __future__ import annotations

from app.services.poc_script import (
    POC_CLI_ERROR,
    poc_cli_block_reason,
    read_poc_code,
    write_poc_code,
)


def test_poc_cli_allows_stub_and_parameterized_http():
    assert poc_cli_block_reason("print('poc')\n") is None
    assert poc_cli_block_reason("") is None
    ok = """
import argparse, urllib.request
p = argparse.ArgumentParser()
p.add_argument("-u", "--url", required=True)
p.add_argument("-c", "--cmd", default="id")
args = p.parse_args()
print(urllib.request.urlopen(args.url).read())
"""
    assert poc_cli_block_reason(ok) is None


def test_poc_cli_rejects_hardcoded_http_target():
    bad = "import requests\nprint(requests.get('http://127.0.0.1:18080/exec?cmd=id').text)\n"
    assert poc_cli_block_reason(bad) == POC_CLI_ERROR
    assert poc_cli_block_reason("curl http://127.0.0.1:18080/x\n") is None


def test_write_and_read_poc_prefers_file(tmp_env, project):
    write_poc_code(project, 9, "print('from-file')\n")
    assert read_poc_code(project, 9, fallback="db") == "print('from-file')\n"
    assert read_poc_code(project, 99, fallback="db") == "db"
