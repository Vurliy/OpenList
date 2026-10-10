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

### 已合入 PR #2950 修复后的镜像发布

生产主程序位于 `work-jp-arm-1`；storage 服务器运行的是 WebDAV 服务，不在其上构建或新增 OpenList 容器。
长任务使用当前 Agent UUID 的专属 tmux。只在专用编译机运行下列 Dockerfile 构建，生产机仅加载镜像并重建原服务：

```bash
docker build --pull=false --build-arg BASE_IMAGE_TAG=ffmpeg \
  --build-arg USE_LOCAL_FRONTEND=true \
  --build-arg BUILD_GIT_COMMIT=<完整后端提交号> \
  --build-arg BUILD_VERSION=<后端版本号> \
  --build-arg BUILD_WEB_VERSION=<随包前端版本号> \
  -t openlist:<发布标识>-<架构> .
```

构建上下文使用已提交的后端源码和明确选定的 `public/dist`，不携带 `.git`、生产配置、数据库或凭据。
上述版本参数用于源码归档不含 Git 元数据时的二进制版本注入；运行镜像同时记录 OCI revision/version 标签。
前端资源未变更时复用已发布定制资源，不在后端修复发布中顺带更新前端。

镜像导出后核对 SHA256，归档到学习项目 `packaged/images/`；ARM 镜像取回后立即经 OCI SDK
执行 `SOFTSTOP` 并确认 `STOPPED`，然后再开展生产发布。生产发布先备份原 Compose 文件和数据库，
保留旧镜像用于回滚；只修改原 OpenList 服务的镜像引用，保持卷、端口和运行参数不变。
部署后核对二进制提交号、容器状态、磁盘/目录容量和 WebDAV 预览，不能只凭首页 HTTP 200 判定完整验收通过。
