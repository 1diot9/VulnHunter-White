# PoC 脚本（可对任意目标复测）

`poc_code` / `vulns/{id}/poc.py` 必须是可独立运行的 Python 3 脚本，给人工、Reviewer 和 Verifier 换目标复测。不要写成只打本次 lab 的一次性片段。

## 与 harness.py 的职责边界

两份脚本不要做同一件事。

| 文件 | 职责 | 何时写 |
| --- | --- | --- |
| `poc.py` | 对**真实运行面**复测：Web / HTTP 面打任意 origin；纯库洞则 `import` 已安装包并调用公开 API | 有 HTTP 利用面，或安装真实包后能复现 |
| `harness.py` | 局部验证沙箱证据：默认抽出函数 + mock；公开入口本身吃 HTTP/请求对象时改为同进程请求级加强验证。由 `RunCode` 落盘。stdout 必须打印运行时实际数据，禁止写死成功字段 | 仅局部验证模式 |

- **禁止**把 harness 的内联源码、mock、TEST 矩阵抄进 `poc.py`。
- **禁止**给纯库洞加未使用的 `-u/--url` / `--proxy`「仅为 CLI 兼容」。
- **harness 输出必须来自运行时**：`harness.py` 须打印调用抽出函数/sink 后的实际返回值、查询结果、命令回显或渲染结果。禁止只打印固定 `SUCCESS` / `VULNERABILITY CONFIRMED`，禁止写死 `success=True` 或 `{"success": true}`，禁止把预期回显写成字面量。判定标签可以有，但必须同时打印实际数据。
- 无 HTTP 面且无法对已安装包复现时：**不要落盘 `poc.py`**，`http_request` 与报告写 API 调用配方即可。SubmitVuln 此时可省略 `poc_code`。

## 必做（有 HTTP 利用面时）
下列条款适用于 Web 洞以及组件库/混合仓里**确有 HTTP 利用面**的 `poc.py`。纯库洞、无 HTTP 面的脚本见文首「职责边界」与文末「组件库」节，不要套用 `-u/--url`。

1. **目标一律 CLI 传入**：用 `argparse`，必填 `-u/--url`（站点 origin，如 `http://1.2.3.4:8080`）。不要写死 `127.0.0.1`、lab 端口或某个 FOFA 主机。
2. **HTTP 代理一律 CLI 传入**：每个 `poc.py` 都必须提供 `--proxy`（可选，默认空字符串=直连），例如 `http://127.0.0.1:8080`。发给目标的全部 HTTP/HTTPS 请求都必须走该参数（`urllib` 用 `ProxyHandler`，`requests`/`httpx` 用 `proxies=`）。不要写死代理地址，也不要只声明参数却不接到客户端。
   - **有 `--proxy` 时，访问 `127.0.0.1` / `localhost` / `::1` 也必须强制走代理。** Python 与 Windows 默认会把本机地址列入代理旁路（`proxy_bypass` / `NO_PROXY` /「对本地地址不使用代理」），只写 `ProxyHandler` 或 `proxies=` 不够。必须覆盖 `urllib.request.proxy_bypass`（及 registry/environment 变体）为永不旁路；若用 `requests`，再把 `requests.utils.should_bypass_proxies` 置为恒 `False` 且 `session.trust_env=False`；若用 `httpx`，用显式 `proxy=` 且 `trust_env=False`。
3. **HTTPS 默认容忍证书不匹配/自签证书**：FOFA 复测、用 IP 访问 HTTPS、或靶场自签证书时，Python 默认校验会报 `SSLCertVerificationError` 并中断。所有 HTTPS 请求须**默认跳过证书校验**（`urllib` 用带 `check_hostname=False` / `verify_mode=CERT_NONE` 的 `SSLContext` 挂到 `HTTPSHandler`；`requests`/`httpx` 默认 `verify=False`），并在 `-u` 为 `https://` 且未传 `--strict-ssl` 时**打印一次告警**，例如：`[!] Warning: HTTPS target skips TLS certificate verification by default (common for IP access or self-signed certs); pass --strict-ssl for strict verification`。可选 `--strict-ssl` 恢复系统默认校验；HTTP 目标不受影响。
4. **漏洞参数可自定义**：凡攻击者本就可控的量都做成可选 CLI，并给安全默认值，使 `python poc.py -u <target_url>` 不传其它参数也能打出代表证据。
   - RCE / 命令注入：`-c/--cmd`（默认如 `id`）。**有回显则把命令输出原样打印到 stdout**（建议加 `Command output:` 前缀）；无回显则打印判定依据（时延、状态码、外带 DNS 等）。
   - 任意文件读 / 路径穿越：`-f/--file`（默认一条敏感路径）。
   - SSRF：`--ssrf-url`（默认内网探测地址）。**有回显则打印目标响应正文**（建议加 `SSRF echo:` 前缀）；**外带内网信息则打印从攻击者信道取回的内容**（建议加 `SSRF exfil:` 前缀，须含目标侧信息，不要只打印「收到回调」）；仅响应差别则打印通/不通对照（开/闭端口或活/死地址的状态码、时延、报错），不要把 URL 反显当成回显。
   - SQLi / SSTI：`--payload`（默认探测句）。
   - 需登录：`--cookie` / `--token`，或 `-U/--user` `-P/--password`。
   - 其它入口（path、id、filename 等）同样做成 CLI，不要写死本次样本。
5. **打印结果**：打印 HTTP 状态、关键响应头、响应正文（过长可截断并注明）。RCE 有回显时单独打印命令输出。打出预期冲击退出码 0，否则非 0。靶场动态下 ConfirmVuln 会系统再跑一遍落盘脚本，非 0 则拒绝确认。
6. **输出中英双语（`--zh`）**：`poc.py` / `harness.py`（及 `harness.*`、攻击链脚本）作者打印的 stdout/stderr 标签、状态、告警、成功/失败判定必须同时准备中英文。**默认英语**；传入 `--zh` 后改打中文。用一份 `(en, zh)` 对照表 + `msg(key, zh)`（或其它语言等价：扫 argv 是否含 `--zh`），禁止只写死中文，也禁止默认输出中英混排。注释、docstring、`argparse` `--help` 仍用英语。目标回显（HTTP 正文、命令输出、文件内容、异常原文）原样打印，不要翻译。
7. 不要写成 notebook 片段、伪代码，或依赖当前工作目录之外的文件。

## 推荐骨架

```python
#!/usr/bin/env python3
import argparse
import os
import ssl
import urllib.request

MSGS = {
    "ssl_warn": (
        "[!] Warning: HTTPS target skips TLS certificate verification by default "
        "(common for IP access or self-signed certs); pass --strict-ssl for strict verification",
        "[!] 警告：HTTPS 目标默认跳过 TLS 证书校验（常见于 IP 访问或自签证书）；传入 --strict-ssl 可恢复严格校验",
    ),
    "status": ("Status:", "状态:"),
    "response": ("Response:", "响应:"),
    "cmd_out": ("Command output:", "命令输出:"),
    "ssrf_echo": ("SSRF echo:", "SSRF 回显:"),
    "ssrf_exfil": ("SSRF exfil:", "SSRF 外带:"),
}

def msg(key: str, zh: bool) -> str:
    en, zh_s = MSGS[key]
    return zh_s if zh else en

def never_bypass(host, **kwargs):
    return False

def ssl_context(*, strict: bool) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if strict:
        return ctx
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

def opener(proxy: str, *, strict_ssl: bool):
    handlers = [urllib.request.HTTPSHandler(context=ssl_context(strict=strict_ssl))]
    if proxy:
        # Force proxy for 127.0.0.1/localhost; do not bypass local addresses.
        os.environ["no_proxy"] = ""
        os.environ["NO_PROXY"] = ""
        urllib.request.proxy_bypass = never_bypass
        if hasattr(urllib.request, "proxy_bypass_environment"):
            urllib.request.proxy_bypass_environment = never_bypass
        if hasattr(urllib.request, "proxy_bypass_registry"):
            urllib.request.proxy_bypass_registry = never_bypass
        handlers.insert(0, urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    return urllib.request.build_opener(*handlers)

def main() -> int:
    p = argparse.ArgumentParser(description="PoC")
    p.add_argument("-u", "--url", required=True, help="Target origin, e.g. http://127.0.0.1:8080")
    p.add_argument("--proxy", default="", help="HTTP proxy, e.g. http://127.0.0.1:8080; empty=direct")
    p.add_argument(
        "--strict-ssl",
        action="store_true",
        help="Strict HTTPS certificate verification (default: skip mismatch/self-signed)",
    )
    p.add_argument(
        "--zh",
        action="store_true",
        help="Print labels/status in Chinese (default: English)",
    )
    p.add_argument("-c", "--cmd", default="id", help="Command to execute (RCE)")
    args = p.parse_args()
    zh = args.zh
    base = args.url.rstrip("/")
    if base.lower().startswith("https://") and not args.strict_ssl:
        print(msg("ssl_warn", zh))
    http = opener(args.proxy, strict_ssl=args.strict_ssl)
    # Send request: http.open(urllib.request.Request(...))
    # requests: verify=args.strict_ssl; override proxy_bypass the same way
    # requests.utils.should_bypass_proxies = lambda url, no_proxy=None: False
    # session.trust_env = False; session.proxies = {"http": args.proxy, "https": args.proxy}
    # print(msg("status", zh), ...); print(msg("response", zh), ...)
    # If echoed: print(msg("cmd_out", zh)); print(output)
    # Return 0 only when the expected impact is observed, else 1
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
```

## 调用示例

```text
python poc.py -u http://TARGET:PORT
python poc.py -u http://TARGET:PORT --zh
python poc.py -u http://TARGET:PORT --proxy http://127.0.0.1:8080
python poc.py -u http://TARGET:PORT -c "whoami"
python poc.py -u http://TARGET:PORT -c "id" --cookie "SESSION=..." --proxy http://127.0.0.1:8080
python poc.py -u https://110.238.73.241
python poc.py -u https://real-domain.com --strict-ssl
python harness.py
python harness.py --zh
```

## Reviewer / Verifier
- 动态验证或互联网复测：先跑 `python vulns/{id}/poc.py -u <该目标>`，按需加 `-c`、`--proxy` 等参数，不要把地址或代理写回脚本。
- **靶场动态收口闸门**：ConfirmVuln 会系统再执行即将落盘的 `poc.py -u <target_url>`；退出码非 0 则拒绝确认。你仍须先自己跑一遍观察冲击。
- **PoC 由 Reviewer 收口**：Worker 交静态草案。写死地址/参数、缺 CLI（含 `--proxy` / HTTPS 证书处理 / `--zh`）、有代理却让 `127.0.0.1` 旁路、HTTPS 因证书校验失败直接中断、默认输出写死中文或中英混排、同链 payload 细节不对，都由 Reviewer Write `poc.py` 并在 ConfirmVuln 传入 `poc_code`。不要为此 ReturnToWorker。
- **debug MCP**：仅当 poc.py 缺失、跑不通或复现失败，且 Reviewer 需要自己改写/调试 PoC 时使用；不是首选验证方式。
- **禁止**换一条利用链或换一个 sink 来让洞过关，也禁止改靶场替 Worker 圆谎。同一条链上的 payload 校准（编码、参数名、鉴权头）不算换链。

## 组件库 / 混合审计对象
当项目 `target_kind` 为 `library` 或 `mixed`：
- 有 HTTP 利用面时，仍遵守上文 `-u/--url` + `--proxy` 合同，且 `poc_code` 必填。
- **纯库洞**以 `harness.py`（`RunCode`）为局部验证证据主路径。公开入口本身吃 HTTP/请求对象时，harness 须调用 `src/` 该 API 并在同进程内发攻击请求（payload 来自请求），不要只拷内部函数；YAML/编解码等无请求面 API 不要包 HTTP。`poc.py` **仅当**安装真实包（pip/npm/maven 等）后能 `import` 公开 API 并打出冲击时才写：最小调用脚本，argparse 可用包路径/版本等参数，**不要** `-u/--url`。不要复制 harness 的内联/mock 测试。
- 无 HTTP 面、也无法对已安装包复现：省略 `poc_code`，不要交空壳或假 HTTP CLI。
- SubmitVuln 的 `http_request` 可写 **API 调用配方**（类/方法/参数），不必是 HTTP 报文；FOFA/X 指纹可写「不适用」。
- harness 同样须支持 `--zh`（Python `argparse`；其它语言扫 argv / `process.argv` / `os.Args` 是否含 `--zh`）。默认英语标签，`--zh` 切中文；注释与 `--help` 仍用英语。stdout 的最终证据必须是运行时实际数据，禁止写死 `success=True` / `{"success": true}` 或只打印 `CONFIRMED`。
