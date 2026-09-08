# TODO.md

## 进行中
- 为其余 fragment 中的存量函数补齐中文函数签名 (入参/出参/异常/示例).
- 将 exec 片段逐步替换为真实 package import, 同时保持测试对 `main.*` 全局的重绑定语义.

## 待办
- 给 `generate_*_page` 的大段 HTML 也迁到 `web/templates`.
- CommandCenterHandler mixin 补类型注解, 消除片段级静态检查噪音.
- 为 Jobs 删除增加浏览器级 smoke (现有 dashboard_smoke 已覆盖 jobs.js 加载).

## 不做
- 重构后不进行 Docker build.
- 重构后不进行离线包 export.
