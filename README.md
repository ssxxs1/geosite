# sing-box-geosite

在 `links.txt` 添加规则集，自动生成 sing-box Source Format（`.json` / `.srs`）和 Mihomo/Clash classical provider（`_clash.yaml`）。fork 后可以添加需要转换的规则集。

AI 总表由 `script/generate_ai.py` 先聚合生成到 `Private/AI.list`。Blackmatrix7 的 OpenAI、Gemini、Claude、Copilot 四个列表作为必需且正向的数据源；任一必需源、核心规则校验或输出安全检查失败时，脚本保留现有文件并退出失败。

```bash
python -m unittest discover -s tests -v
python script/generate_ai.py
python main.py
```

本地环境如果 CA 证书链异常，可临时为生成命令添加 `--insecure`；CI 默认始终启用 TLS 校验。`main.py --skip-srs` 仅用于本地缺少 sing-box 时检查文本产物，正式生成必须成功编译 `.srs`。

仓库 Settings ----> Actions ----> General ----> Workflow permissions ----> Read and write permissions 勾选上

规则集源文件写法eg:

```json
{
  "tag": "geosite-wechat",
  "type": "remote",
  "format": "source",
  "url": "https://raw.githubusercontent.com/Toperlock/sing-box-geosite/main/wechat.json",
  "download_detour": "auto"
}
```

# 致谢（排名不分先后）

[@izumiChan16](https://github.com/izumiChan16)

[@ifaintad](https://github.com/ifaintad)

[@NobyDa](https://github.com/NobyDa)

[@blackmatrix7](https://github.com/blackmatrix7)

[@DivineEngine](https://github.com/DivineEngine)
