# sing-box-geosite

将 Clash、Surge、QuantumultX 等常见格式的远程规则列表转换为 sing-box Source Format（JSON），并编译为二进制 SRS。GitHub Actions 每天自动同步上游规则。

## 使用规则集

```json
{
  "tag": "geosite-wechat",
  "type": "remote",
  "format": "binary",
  "url": "https://raw.githubusercontent.com/akaagiao1/sing-box-geosite/main/rule/WeChat.srs",
  "download_detour": "auto"
}
```

如需使用 JSON，将 `format` 改为 `source`，并把 URL 后缀改为 `.json`。

## 添加规则源

在 [`links.txt`](links.txt) 中每行添加一个 URL。支持：

- Clash YAML（`payload` 列表）
- Surge / QuantumultX 逗号分隔规则
- 每行一个域名、域名后缀或 CIDR 的纯文本列表

输出文件名取自 URL 的文件名。同名来源会导致校验失败，以避免规则被静默覆盖。

当一个来源同时包含域名和 IP CIDR 时，会保留原始合并文件，并额外生成：

- `<名称>_domain.json/.srs`：仅包含域名匹配规则，适合 DNS 和域名路由
- `<名称>_ip.json/.srs`：仅包含目标/源 IP CIDR，适合 IP 路由

保留合并文件是为了兼容已有配置。新配置建议分别引用 domain 和 IP 文件。

Fork 后需要在 `Settings → Actions → General → Workflow permissions` 中启用 **Read and write permissions**，自动更新才能推送生成文件。

## 本地运行

需要 Python 3.9+ 和 `sing-box`：

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python main.py
```

仅生成 JSON（无需安装 sing-box）：

```bash
python main.py --no-compile
```

运行测试：

```bash
python -m unittest discover -v
```

## 致谢

感谢 [izumiChan16](https://github.com/izumiChan16)、[ifaintad](https://github.com/ifaintad)、[NobyDa](https://github.com/NobyDa)、[blackmatrix7](https://github.com/blackmatrix7) 和 [DivineEngine](https://github.com/DivineEngine) 提供的规则与思路。
