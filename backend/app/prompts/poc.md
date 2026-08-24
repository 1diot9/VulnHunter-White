# PoC 脚本（可对任意目标复测）

`poc_code` / `vulns/{id}/poc.py` 必须是可独立运行的 Python 3 脚本，给人工、Reviewer 和 Verifier 换目标复测。不要写成只打本次 lab 的一次性片段。

## 必做
1. **目标一律 CLI 传入**：用 `argparse`，必填 `-u/--url`（站点 origin，如 `http://1.2.3.4:8080`）。不要写死 `127.0.0.1`、lab 端口或某个 FOFA 主机。
2. **HTTP 代理一律 CLI 传入**：每个 `poc.py` 都必须提供 `--proxy`（可选，默认空字符串=直连），例如 `http://127.0.0.1:8080`。发给目标的全部 HTTP/HTTPS 请求都必须走该参数（`urllib` 用 `ProxyHandler`，`requests`/`httpx` 用 `proxies=`）。不要写死代理地址，也不要只声明参数却不接到客户端。
   - **有 `--proxy` 时，访问 `127.0.0.1` / `localhost` / `::1` 也必须强制走代理。** Python 与 Windows 默认会把本机地址列入代理旁路（`proxy_bypass` / `NO_PROXY` /「对本地地址不使用代理」），只写 `ProxyHandler` 或 `proxies=` 不够。必须覆盖 `urllib.request.proxy_bypass`（及 registry/environment 变体）为永不旁路；若用 `requests`，再把 `requests.utils.should_bypass_proxies` 置为恒 `False` 且 `session.trust_env=False`；若用 `httpx`，用显式 `proxy=` 且 `trust_env=False`。
3. **HTTPS 默认容忍证书不匹配/自签证书**：FOFA 复测、用 IP 访问 HTTPS、或靶场自签证书时，Python 默认校验会报 `SSLCertVerificationError` 并中断。所有 HTTPS 请求须**默认跳过证书校验**（`urllib` 用带 `check_hostname=False` / `verify_mode=CERT_NONE` 的 `SSLContext` 挂到 `HTTPSHandler`；`requests`/`httpx` 默认 `verify=False`），并在 `-u` 为 `https://` 且未传 `--strict-ssl` 时**打印一次告警**，例如：`[!] 警告: HTTPS 目标默认跳过 TLS 证书校验（常见于 IP 访问或自签证书）；严格校验请加 --strict-ssl`。可选 `--strict-ssl` 恢复系统默认校验；HTTP 目标不受影响。
4. **漏洞参数可自定义**：凡攻击者本就可控的量都做成可选 CLI，并给安全默认值，使 `python poc.py -u <target_url>` 不传其它参数也能打出代表证据。
   - RCE / 命令注入：`-c/--cmd`（默认如 `id`）。**有回显则把命令输出原样打印到 stdout**（建议加 `命令输出:` 前缀）；无回显则打印判定依据（时延、状态码、外带 DNS 等）。
   - 任意文件读 / 路径穿越：`-f/--file`（默认一条敏感路径）。
   - SSRF：`--ssrf-url`（默认内网探测地址）。**有回显则打印目标响应正文**（建议加 `SSRF 回显:` 前缀）；仅响应差别则打印通/不通对照（开/闭端口或活/死地址的状态码、时延、报错），不要把 URL 反显当成回显。
   - SQLi / SSTI：`--payload`（默认探测句）。
   - 需登录：`--cookie` / `--token`，或 `-U/--user` `-P/--password`。
   - 其它入口（path、id、filename 等）同样做成 CLI，不要写死本次样本。
5. **打印结果**：打印 HTTP 状态、关键响应头、响应正文（过长可截断并注明）。RCE 有回显时单独打印命令输出。打出预期冲击退出码 0，否则非 0。靶场动态下 ConfirmVuln 会系统再跑一遍落盘脚本，非 0 则拒绝确认。
6. 不要写成 notebook 片段、伪代码，或依赖当前工作目录之外的文件。

## 推荐骨架

```python
#!/usr/bin/env python3
import argparse
import os
import ssl
import urllib.request

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
        # 有代理时 127.0.0.1/localhost 也必须走代理，禁止本机旁路。
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
    p.add_argument("-u", "--url", required=True, help="目标 origin，如 http://127.0.0.1:8080")
    p.add_argument("--proxy", default="", help="HTTP 代理，如 http://127.0.0.1:8080；空则直连")
    p.add_argument(
        "--strict-ssl",
        action="store_true",
        help="严格校验 HTTPS 证书（默认跳过不匹配/自签证书）",
    )
    p.add_argument("-c", "--cmd", default="id", help="要执行的命令（RCE）")
    args = p.parse_args()
    base = args.url.rstrip("/")
    if base.lower().startswith("https://") and not args.strict_ssl:
        print(
            "[!] 警告: HTTPS 目标默认跳过 TLS 证书校验（常见于 IP 访问或自签证书）；"
            "严格校验请加 --strict-ssl"
        )
    http = opener(args.proxy, strict_ssl=args.strict_ssl)
    # 发请求：http.open(urllib.request.Request(...))
    # requests: verify=args.strict_ssl；同样覆盖 proxy_bypass
    # requests.utils.should_bypass_proxies = lambda url, no_proxy=None: False
    # session.trust_env = False; session.proxies = {"http": args.proxy, "https": args.proxy}
    # print("状态:", ...); print("响应:", ...)
    # 有回显: print("命令输出:"); print(output)
    # 打出预期冲击才 return 0，否则 return 1
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
```

## 调用示例

```text
python poc.py -u http://TARGET:PORT
python poc.py -u http://TARGET:PORT --proxy http://127.0.0.1:8080
python poc.py -u http://TARGET:PORT -c "whoami"
python poc.py -u http://TARGET:PORT -c "id" --cookie "SESSION=..." --proxy http://127.0.0.1:8080
python poc.py -u https://110.238.73.241
python poc.py -u https://real-domain.com --strict-ssl
```

## Reviewer / Verifier
- 动态验证或互联网复测：先跑 `python vulns/{id}/poc.py -u <该目标>`，按需加 `-c`、`--proxy` 等参数，不要把地址或代理写回脚本。
- **靶场动态收口闸门**：ConfirmVuln 会系统再执行即将落盘的 `poc.py -u <target_url>`；退出码非 0 则拒绝确认。你仍须先自己跑一遍观察冲击。
- **PoC 由 Reviewer 收口**：Worker 交静态草案。写死地址/参数、缺 CLI（含 `--proxy` / HTTPS 证书处理）、有代理却让 `127.0.0.1` 旁路、HTTPS 因证书校验失败直接中断、同链 payload 细节不对，都由 Reviewer Write `poc.py` 并在 ConfirmVuln 传入 `poc_code`。不要为此 ReturnToWorker。
- **debug MCP**：仅当 poc.py 缺失、跑不通或复现失败，且 Reviewer 需要自己改写/调试 PoC 时使用；不是首选验证方式。
- **禁止**换一条利用链或换一个 sink 来让洞过关，也禁止改靶场替 Worker 圆谎。同一条链上的 payload 校准（编码、参数名、鉴权头）不算换链。

## 组件库 / 混合审计对象
当项目 `target_kind` 为 `library` 或 `mixed`：
- 有 HTTP 利用面时，仍遵守上文 `-u/--url` + `--proxy` 合同。
- **纯库洞**以 `harness.py`（`RunCode`）为证据主路径；`poc.py` 可为调用公开 API 的最小脚本（argparse 可用包路径/版本等参数，不强制 HTTP origin）。
- SubmitVuln 的 `http_request` 可写 **API 调用配方**（类/方法/参数），不必是 HTTP 报文；FOFA/X 指纹可写「不适用」。
