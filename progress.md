# progress.md

## 2026-09-08 长期维护重构

### 已完成
- 将 2 万行 `main.py` 拆为 `subscraper/fragments/` 片段, 由根目录 `main.py` 加载进同一命名空间, 兼容现有 `import main` 测试.
- 仪表盘从内嵌字符串抽出到 `web/templates` + `web/static/{css,js}`, 单文件控制在 600 行内.
- HTTP handler 拆为 Auth/Agent/GET/POST mixin.
- Jobs 页改为筛选芯片 + 搜索 + 卡片式布局.
- 新增 Job 删除: 排队直接移除, 运行中在检查点取消且不写入 completed, 已完成删除内存与 SQLite.
- `log()` 改为 `logging` 模块, UTC 格式.
- 新增 `test_jobs_delete.py`. 仪表盘 smoke 改为按 JS manifest 拼接.
- Dockerfile 增加 `subscraper/` 与 `web/` 复制. 按需求未执行 build / export.
- 修复 Launch Scan 404: 多 `<script>` 无法共享 const/let, 表单退化成 GET `/?domain=`; 现拼接为 `/static/js/dashboard.js`, GET `/` 忽略 query.

### 验证
- `python3 -m pytest test_jobs_delete.py test_dashboard_loads.py test_main.py -q`

### 未做
- 不执行 Docker build, 不执行离线 export.
- 历史函数的中文签名仍在逐步补齐, 见 TODO.md.
