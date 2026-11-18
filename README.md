# sing-box-geosite

自动化规则集转换与规则雷达巡检中心。读取 `links.txt` 与 `Private/` 规则集，自动下载并编译为 sing-box（`.json` / `.srs`）、Mihomo（`.mrs` / `_clash.yaml`）与 Quantumult X（`.list`）格式，并通过 GitHub Actions 持续自动化分发与巡检。

---

## 🌟 核心特性

### 1. 多格式高兼容编译

- **sing-box**：支持编译为标准 Source JSON（`.json`）以及高性能二进制规则集（`.srs`）。
- **Mihomo / Clash**：支持编译为标准 classical provider（`_clash.yaml`）以及智能二进制规则集（`.mrs`，根据 behavior 自动划分为 domain / ipcidr）。
- **容错韧性**：单源拉取异常时自动回退复用本地历史版本或从 GitHub Release 兜底恢复；sing-box 编译异常不阻断 Clash 与 MRS 生成。

### 2. AI 规则集深度治理与清洗

AI 规则总表由 `script/generate_ai.py` 聚合生成至 `Private/AI.list`，并与 `OpenAI`、`Copilot`、`Claude`、`Gemini` 等分集统一执行安全清洗：

- **机房 ASN 严格隔离**：严禁整段机房 ASN（DigitalOcean 14061、Vultr 20473）进 AI 规则，杜绝非 AI 流量与代理节点被错误劫持；
- **全网埋点与遥测拦截**：自动剔除非 AI 相关的通用分析/埋点/错误上报（如 Sentry、AppsFlyer、Segment 等，同时显式豁免 Claude/AI 登录支付所需的 `auth0.com`、`stripe*` 及特定 Datadog 日志端点）；
- **时间授时保护**：自动识别公共 NTP 授时与时间同步域名，避免时间服务流量异常；
- **单标签非法后缀过滤**：自动拦截上游单标签后缀脏数据（如 `.ms`、`.azure` 等，仅保留 `.cn`、`.aws` 等合法顶级域）。

### 3. 📡 规则雷达巡检与证书透明度探针 (Rule Radar Sentinel)

为解决部分常年不更新上游转为本地独立维护（`Private/*.list`）后的**时效性滞后**问题，内置了双核雷达自动化监控系统：

- **双核监控**：
  - **社区源差分**：持续监控 MetaCubeX 等活跃社区规则集最新变动；
  - **超前方案·证书透明度 (CT Logs)**：针对 Anthropic / OpenAI / xAI 等顶级资产，实时查询全球公开 SSL/TLS 证书签发日志，提前 1-2 周捕获官方活体业务子域。
- **两道漏斗与智能子域吸收 (Subsumption Check)**：
  - **子域覆盖过滤**：若新发现的子域已被现有规则后缀包含（例如已有 `DOMAIN-SUFFIX,claude.com`，则新发现的 `downloads.claude.com` 会在第一步被**静默剔除**），零噪音打扰；仅报告全新根域或独立资产。
  - **红队级安全校验**：彻底防御 CRLF 换行注入、纯 IP 污染与 multi-SAN 证书跨域泄露。
- **CI 自动化与双通道提醒**：
  - 每周一上午定时触发（支持手动触发）；
  - 发现新资产时自动在 `radar/discovery-YYYYMMDD` 分支生成变更并创建 **Draft PR**，通过 GitHub 官方通知与邮件提醒仓库管理员；
  - 预留 SMTP 直连通道，支持在 Secrets 配置后直接发送告警战报邮件至个人邮箱。

---

## 🚀 常用命令

```bash
# 1. 运行全量单元测试 (包含规则清洗算法与雷达探针全套测试)
python3 -m unittest discover -s tests -v

# 2. 运行规则雷达巡检 (查看当前是否有未收录的全新资产)
python3 script/diff_radar.py

# 3. 运行规则雷达并将新发现一键合并写入本地 Private/*.list
python3 script/diff_radar.py --apply

# 4. 聚合生成 AI 核心规则表
python3 script/generate_ai.py

# 5. 运行全量规则转换与二进制编译 (输出至 rules/ 目录)
python3 main.py
```

---

## 📦 输出格式说明

| 格式                 | 生成工具                  | 适用客户端 / 用途                                   | 推荐程度   |
| :------------------- | :------------------------ | :-------------------------------------------------- | :--------- |
| `rules/*.list`       | 内置转换器                | **Quantumult X** 原生标准分流规则集，可直接远程订阅 | 🌟🌟🌟🌟🌟 |
| `rules/*.srs`        | sing-box rule-set compile | **sing-box** 二进制规则集，加载极速、内存占用低     | 🌟🌟🌟🌟🌟 |
| `rules/*.json`       | 内置转换器                | **sing-box** Source Format 规则集                   | 🌟🌟🌟     |
| `rules/*.mrs`        | mihomo convert-ruleset    | **Mihomo** 二进制规则集，分流性能最优               | 🌟🌟🌟🌟🌟 |
| `rules/*_clash.yaml` | 内置转换器                | **Mihomo / Clash** classical rule-provider          | 🌟🌟🌟     |

---

## ⚙️ 仓库配置指南

### 1. 必须开启的工作流读写权限

为了使 GitHub Actions 能够正常提交编译后的规则集以及自动创建巡检 Draft PR：

1. 打开 GitHub 仓库 **Settings** -> **Actions** -> **General**；
2. 找到 **Workflow permissions**，选择 **Read and write permissions**；
3. 勾选 **Allow GitHub Actions to create and approve pull requests** 并保存。

### 2. 自定义邮件通知配置 (可选)

如果需要雷达探针在发现新域名时直接通过邮件通知你，请在 **Settings** -> **Secrets and variables** -> **Actions** 中添加：

- `SMTP_SERVER`：SMTP 服务器地址（如 `smtp.qq.com` 或 `smtp.gmail.com`）；
- `SMTP_PORT`：端口（通常为 `465` 或 `587`）；
- `SMTP_USERNAME`：发件邮箱账号；
- `SMTP_PASSWORD`：邮箱授权码 / 密码；
- `NOTIFICATION_EMAIL`：接收提醒的目标邮箱（留空默认发送至发件人）。

---

## 📌 特殊模块说明

- **`Private/HttpDNS.snippet` 模块**：此文件为 Quantumult X 专用的 HTTPDNS 拦截重写模块（包含针对 `amdc.alipay.com`、`dns.jd.com` 等域名的 MITM 解密），目的是强制国内 App 回退到系统自建 DNS（如 MosDNS / aliyun-doh）。**此模块不属于普通分流规则集，请根据自建 DNS 实际需求单独订阅**。

---

# 致谢（排名不分先后）

[@blackmatrix7](https://github.com/blackmatrix7)  
[@DivineEngine](https://github.com/DivineEngine)  
[@MetaCubeX](https://github.com/MetaCubeX)  
[@ddgksf2013](https://github.com/ddgksf2013)  
[@SukkaW](https://github.com/SukkaW)  
[@ConnersHua](https://github.com/ConnersHua)  
[@dler-io](https://github.com/dler-io)  
[@RocM301](https://github.com/RocM301)  
[@shangrenxi](https://github.com/shangrenxi)  
[@Accademia](https://github.com/Accademia)
