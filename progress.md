# progress.md

## 2026-09-12 nikto 缺 XML::Writer

### 问题
GitHub nikto 2.6.1 `load_modules()` 硬依赖 `XML::Writer`. 镜像只装了 `perl` + `libnet-ssleay-perl`, 扫描时报 `ERROR: Required module not found: XML::Writer`.

### 已完成
- Dockerfile 增加 `libxml-writer-perl`.
- 当前运行中的 `subscraper` 容器已 apt 安装该包 (重建镜像前仅当前实例有效).
- `TOOL_NOTES` 注明 XML::Writer.

### 验证
- 容器内 `perl -MXML::Writer` → OK
- `nikto -Help` 正常输出 Options, 不再报 XML::Writer
- `nikto -h http://127.0.0.1` 进入连接阶段 (127.0.0.1:80 无服务, 与模块无关)

## 2026-09-11 移除 Amass, DNS 爆破改 dnsx

### 已完成
- 从 TOOLS / PIPELINE_STEPS / 配置 / Docker / Settings UI 删除 Amass.
- 域名发现改为 `dnsx -silent -d DOMAIN -w WORDLIST`, 源标记 `dnsx`.
- `amass_done` 迁移为内部 `dns_brute_done` (导入/单主机仍跳过爆破, 下游仍做 dnsx 校验).
- IP/CIDR 仍跳过 DNS.

### 验证
- `python3 -c "import main; assert 'amass' not in main.TOOLS"` → pipeline `dnsx, port_scan, ...`
- `python3 -m pytest test_intranet.py::TestDnsxBrute test_intranet.py::TestIntranetPipelineConstants test_tooling_and_js_overview.py::TestWorkflowDiagram test_jobs_delete.py test_dashboard_loads.py -q` → 23 passed



## 2026-09-08 内网长期维护重构

### 已完成
- 项目定位改为纯内网资产发现: 输入 DOMAIN / IP / CIDR, 不做互联网 OSINT.
- 删除被动收集与外网 API: subfinder, assetfinder, findomain, sublist3r, crt.sh, github-subdomains, waybackurls, gau, Amass/Subfinder API key.
- 新包模块 (可单测, 不 exec):
  - `subscraper/targets.py` 解析域名/IP/CIDR
  - `subscraper/discovery/ports.py` nmap 命令与 XML 解析
  - `subscraper/discovery/vhost.py` ffuf Host 头 vhost
- 流水线步骤: amass DNS 爆破 -> dnsx -> nmap 端口/服务 -> httpx -> vhost_enum -> screenshots -> nuclei -> jsscan -> nikto
- IP/CIDR 跳过 DNS 爆破, 直接 nmap.
- vhost 枚举进入自动流水线 (不再仅手动).
- 截图 (gowitness) 与 nuclei/nikto 漏扫保留, 只打已发现的 Web 资产.
- Settings/Launch/HowTo/Dockerfile 去掉被动工具与 API Keys 页.
- 测试: `test_intranet.py`; 更新 tooling/jobs/dashboard 相关断言.

### 验证
- `python3 -m pytest test_intranet.py test_tooling_and_js_overview.py test_jobs_delete.py test_dashboard_loads.py test_tool_workers.py -q` → 116 passed
- `python3 -c "import main; ... parse_scan_target('https://10.0.0.8:8443/a')"` → IPv4 目标

### 未做
- 不执行 Docker build / 离线 export.
- exec 片段尚未全部改为 package import (jobs/web handler 仍走 fragments).
