# OpenList 定制后端生产工作树 (openlist-custom)

> **上级索引 / 被引用自**：[openlist/source code/README.md](../README.md)

本目录是 OpenList 后端服务的**专用定制生产 Worktree**，绑定于 `custom-main` 分支，与官方主干 `openlist/` 共享底层 Git 对象库。

---

## 核心定制特性与架构

1. **`WebDavTicket` 独立驱动 (`drivers/webdav_ticket`)**：
   - 专用外部 WebDAV 签名直链驱动，与原生 WebDAV 驱动完全物理隔离；
   - 实现了基于 HMAC-SHA256 的 Ticket 签发与两阶段 Exchange 握手。
2. **WebDAV 目录大小与配额统计**：
   - 实现了 RFC 4331 配额查询以及与 WebDAV 宿主机本地 `dirsize-worker` 端点的异步批量查询和缓存管理。
3. **安全撤销机制 (`server/handles/webdav_auth.go`)**：
   - 支持多级会话撤销与状态清理。
4. **存储容量探测异步解耦与 Singleflight 保护**：
   - 解耦请求 Context，提供 15 秒独立超时与 Singleflight 并发合并保护。

---

## 常用操作与构建命令

```bash
# 同步官方最新代码
git fetch origin
git rebase origin/main

# 编译与构建
# 遵循《生产与编译隔离原则》，ARM 镜像统一在 work-de-arm-1 上构建，X86 镜像在 intranet-master-1 上构建
```
