from __future__ import annotations

from app.services.poc_script import (
    LIBRARY_POC_FAKE_HTTP_CLI_ERROR,
    POC_CLI_ERROR,
    POC_HARNESS_SHAPE_ERROR,
    POC_I18N_ERROR,
    POC_LAB_RUN_ERROR,
    poc_cli_block_reason,
    poc_lab_run_block_reason,
    poc_required_for_submit,
    read_poc_code,
    write_poc_code,
)


def test_poc_cli_allows_stub_and_parameterized_http():
    assert poc_cli_block_reason("print('poc')\n") is None
    assert poc_cli_block_reason("") is None
    ok = """
import argparse, ssl, urllib.request
p = argparse.ArgumentParser()
p.add_argument("-u", "--url", required=True)
p.add_argument("--proxy", default="")
p.add_argument("--strict-ssl", action="store_true")
p.add_argument("-c", "--cmd", default="id")
p.add_argument("--zh", action="store_true")
urllib.request.proxy_bypass = lambda host, **kw: False
urllib.request.HTTPSHandler(context=ssl.create_default_context())
args = p.parse_args()
print(urllib.request.urlopen(args.url).read())
"""
    assert poc_cli_block_reason(ok) is None


def test_poc_cli_rejects_hardcoded_http_target():
    bad = "import requests\nprint(requests.get('http://127.0.0.1:18080/exec?cmd=id').text)\n"
    assert poc_cli_block_reason(bad) == POC_CLI_ERROR
    assert poc_cli_block_reason("curl http://127.0.0.1:18080/x\n") is None
    # library/mixed with an HTTP client still follows the web CLI contract
    assert poc_cli_block_reason(bad, target_kind="library") == POC_CLI_ERROR
    lib_api = """
import argparse
from pkg.api import parse
p = argparse.ArgumentParser()
p.add_argument("--artifact", default="target.jar")
p.add_argument("--zh", action="store_true")
args = p.parse_args()
print(parse(args.artifact))
"""
    assert poc_cli_block_reason(lib_api, target_kind="library") is None
    assert poc_cli_block_reason(lib_api, target_kind="mixed") is None



def test_poc_cli_rejects_http_without_proxy_flag():
    no_proxy = """
import argparse, urllib.request
p = argparse.ArgumentParser()
p.add_argument("-u", "--url", required=True)
args = p.parse_args()
print(urllib.request.urlopen(args.url).read())
"""
    assert poc_cli_block_reason(no_proxy) == POC_CLI_ERROR
    hardcoded_proxy = """
import argparse, urllib.request
p = argparse.ArgumentParser()
p.add_argument("-u", "--url", required=True)
args = p.parse_args()
opener = urllib.request.build_opener(
    urllib.request.ProxyHandler({"http": "http://127.0.0.1:8080"})
)
print(opener.open(args.url).read())
"""
    assert poc_cli_block_reason(hardcoded_proxy) == POC_CLI_ERROR


def test_poc_cli_rejects_http_without_ssl_handling():
    no_ssl = """
import argparse, urllib.request
p = argparse.ArgumentParser()
p.add_argument("-u", "--url", required=True)
p.add_argument("--proxy", default="")
urllib.request.proxy_bypass = lambda host, **kw: False
args = p.parse_args()
print(urllib.request.urlopen(args.url).read())
"""
    assert poc_cli_block_reason(no_ssl) == POC_CLI_ERROR


def test_poc_cli_rejects_proxy_that_bypasses_localhost():
    bypasses = """
import argparse, urllib.request
p = argparse.ArgumentParser()
p.add_argument("-u", "--url", required=True)
p.add_argument("--proxy", default="")
args = p.parse_args()
handler = urllib.request.ProxyHandler({"http": args.proxy, "https": args.proxy})
print(urllib.request.build_opener(handler).open(args.url).read())
"""
    assert poc_cli_block_reason(bypasses) == POC_CLI_ERROR


def test_write_and_read_poc_prefers_file(tmp_env, project):
    write_poc_code(project, 9, "print('from-file')\n")
    assert read_poc_code(project, 9, fallback="db") == "print('from-file')\n"
    assert read_poc_code(project, 99, fallback="db") == "db"


def test_poc_lab_run_requires_url_flag():
    assert poc_lab_run_block_reason("") == POC_LAB_RUN_ERROR
    assert poc_lab_run_block_reason("print('poc')\n") == POC_LAB_RUN_ERROR
    ok = """
import argparse
p = argparse.ArgumentParser()
p.add_argument("-u", "--url", required=True)
p.add_argument("--proxy", default="")
p.add_argument("--strict-ssl", action="store_true")
args = p.parse_args()
print(args.url)
"""
    assert poc_lab_run_block_reason(ok) is None


def test_library_poc_rejects_unused_http_cli():
    dummy = """
import argparse
from pkg.api import parse
p = argparse.ArgumentParser()
p.add_argument("-u", "--url", default="", help="Accepted for CLI compatibility")
p.add_argument("--proxy", default="", help="Accepted for CLI compatibility")
print(parse("../etc/passwd"))
"""
    assert poc_cli_block_reason(dummy, target_kind="library") == LIBRARY_POC_FAKE_HTTP_CLI_ERROR
    assert poc_cli_block_reason(dummy, target_kind="mixed") == LIBRARY_POC_FAKE_HTTP_CLI_ERROR
    assert poc_cli_block_reason(dummy) is None


def test_poc_rejects_harness_shaped_copy():
    harnessy = '''
"""Inlined from src/pkg/core.py. The sandbox lacks yaml so _load_yaml_file is mocked."""
_MOCK_YAML_DATA = {}
def _load_yaml_file(path):
    return _MOCK_YAML_DATA.get(path.name, {})
print("bypass")
'''
    assert poc_cli_block_reason(harnessy) == POC_HARNESS_SHAPE_ERROR
    assert poc_cli_block_reason(harnessy, target_kind="library") == POC_HARNESS_SHAPE_ERROR


def test_poc_cli_requires_zh_flag():
    no_zh = """
import argparse, ssl, urllib.request
p = argparse.ArgumentParser()
p.add_argument("-u", "--url", required=True)
p.add_argument("--proxy", default="")
p.add_argument("--strict-ssl", action="store_true")
urllib.request.proxy_bypass = lambda host, **kw: False
urllib.request.HTTPSHandler(context=ssl.create_default_context())
args = p.parse_args()
print(urllib.request.urlopen(args.url).read())
"""
    assert poc_cli_block_reason(no_zh) == POC_I18N_ERROR
    with_zh = no_zh.replace(
        'p.add_argument("--strict-ssl", action="store_true")',
        'p.add_argument("--strict-ssl", action="store_true")\n'
        'p.add_argument("--zh", action="store_true")',
    )
    assert poc_cli_block_reason(with_zh) is None


def test_library_poc_requires_zh_flag():
    no_zh = """
import argparse
from pkg.api import parse
p = argparse.ArgumentParser()
p.add_argument("--artifact", default="target.jar")
args = p.parse_args()
print(parse(args.artifact))
"""
    assert poc_cli_block_reason(no_zh, target_kind="library") == POC_I18N_ERROR
    with_zh = no_zh.replace(
        'p.add_argument("--artifact", default="target.jar")',
        'p.add_argument("--artifact", default="target.jar")\n'
        'p.add_argument("--zh", action="store_true")',
    )
    assert poc_cli_block_reason(with_zh, target_kind="library") is None
    assert poc_cli_block_reason(with_zh, target_kind="mixed") is None


def test_poc_required_for_submit_library_without_http():
    assert poc_required_for_submit(target_kind="web", http_request="Parser.parse(x)") is True
    assert poc_required_for_submit(
        target_kind="library",
        http_request="RecipeConfig.parse(path, tools=['execute_command'])",
    ) is False
    assert poc_required_for_submit(
        target_kind="library",
        http_request="GET /x HTTP/1.1\nHost: x\n",
    ) is True
    assert poc_required_for_submit(
        target_kind="mixed",
        http_request="API: Parser.parse(untrusted)",
        poc_code="import urllib.request\nprint(1)\n",
    ) is True

