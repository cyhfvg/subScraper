# TODO.md

## 进行中
- 将剩余 `subscraper/fragments/` exec 片段替换为真实 package import, 保持测试对 `main.*` 的重绑定.

## 待办
- `generate_*_page` 大段 HTML 迁到 `web/templates`.
- CommandCenterHandler mixin 补类型注解.
- 为 Launch (IP/CIDR) 与 Jobs 删除补浏览器 smoke.
- 内网默认 wordlist 随仓库提供一份短字典 (当前仍需用户自备).

## 不做
- 不恢复任何互联网被动源 (crt.sh / subfinder / wayback 等).
- 不恢复 Amass; 内网 DNS 爆破只用 dnsx.
- 重构后不进行 Docker build.
- 重构后不进行离线包 export.
