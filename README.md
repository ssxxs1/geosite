# sing-box-geosite

在 `links.txt` 添加规则集，自动生成 sing-box Source Format（`.json` / `.srs`）、Mihomo 二进制规则集（`.mrs`）和 Mihomo/Clash classical provider（`_clash.yaml`）。内置多级容错与冗余机制：单源拉取异常自动回退复用本地历史版本或从 GitHub Release 兜底恢复；sing-box 编译异常不阻断 Clash 与 MRS 生成。fork 后可以添加需要转换的规则集。

AI 总表由 `script/generate_ai.py` 聚合生成至 `Private/AI.list`，并与 `OpenAI`、`Copilot`、`Claude`、`Gemini` 等分集统一执行规则清洗：
- 严格拦截整段机房 ASN（DigitalOcean 14061、Vultr 20473），防止非 AI 流量与代理节点被错误劫持；
- 拦截非 AI 相关的通用分析/埋点/支付/错误上报/NTP 授时域名；
- 拦截上游单标签后缀脏数据（如 `.ms`、`.azure` 等，仅保留 `.cn` 等合法顶级域）。

```bash
# 本地测试与构建
python -m unittest discover -s tests -v
python script/generate_ai.py
python main.py
```

### 模块说明与注意事项
1. **订阅格式**：sing-box 推荐订阅 `rule/*.srs`（二进制）或 `.json`；Mihomo 推荐订阅 `rule/*.mrs`（二进制）或 `*_clash.yaml`。
2. **`Private/HttpDNS.snippet` 模块**：此文件为 Quantumult X 专用的 HTTPDNS 拦截重写模块（包含针对 `amdc.alipay.com`、`dns.jd.com` 等少量域名的 MITM 解密），目的是强制国内 App 回退到系统自建 DNS（如 MosDNS / aliyun-doh）。**此模块不属于普通分流规则集，请根据自建 DNS 需求单独订阅**。
3. **构建安全**：本地 CA 证书链异常时可加 `--insecure`；CI 自动化构建已锁死 sing-box 与 mihomo 核心版本并执行 SHA256 完整性校验。

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
