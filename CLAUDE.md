# geosite — sing-box/mihomo 规则集自动转换器

## 项目概述
Python 脚本项目。读取 `links.txt` 中的规则集源链接，自动下载并转换为 sing-box（`.json` / `.srs`）和 mihomo（`.mrs`）格式，输出到 `rule/` 目录。通过 GitHub Actions 自动化运行。

## 技术栈
- Python 3（无虚拟环境，依赖系统/CI 环境预装）
- 主要依赖：`pandas` / `requests` / `pyyaml` / `ipaddress`
- 外部命令：`sing-box`（生成 .srs）、`mihomo`（生成 .mrs，可选）
- 自动化：GitHub Actions

## 目录结构
```
geosite/
├── main.py           # 核心转换脚本（入口）
├── links.txt         # 规则集源链接列表（每行一个 URL，# 开头为注释）
├── rule/             # 输出目录（自动生成的 .json / .srs / .mrs 文件）
├── emby.json         # 预置规则集示例（Emby）
├── wechat.json       # 预置规则集示例（WeChat）
├── .github/
│   └── workflows/    # GitHub Actions 自动运行工作流
└── .claude/          # AI 配置（勿修改）
```

## 常用命令
```bash
# 运行转换（需本地安装 pandas / requests / pyyaml）
python main.py

# 安装依赖（如无虚拟环境）
pip install pandas requests pyyaml
```

## 添加新规则集流程
1. 在 `links.txt` 中追加规则集源 URL（支持 `.yaml` / `.txt` / `.list` 格式）
2. 推送到 GitHub → Actions 自动触发转换 → `rule/` 目录更新

## 输出格式说明
| 格式 | 工具 | 用途 |
|------|------|------|
| `.json` | sing-box | sing-box Source Format 规则集 |
| `.srs` | sing-box rule-set compile | sing-box 二进制规则集 |
| `_clash.yaml` | 内置转换器 | mihomo/Clash classical rule-provider |

## 注意事项
- `links.txt` 中以 `#` 开头的行为注释，会自动跳过
- 本地需安装 `sing-box` 才能生成 `.srs`；正式运行缺少或编译失败时会退出失败，避免提交陈旧二进制文件
- `rule/` 目录内容由脚本自动管理，不要手动放置文件
- 规则集转换支持 YAML payload 格式、CSV 格式和标准 list 格式
