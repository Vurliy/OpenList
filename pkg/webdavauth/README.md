# OpenList WebDAV ticket

开启 `webdav_auth_enabled` 后，OpenList 每次从网页端生成或打开直接 WebDAV 链接都会追加新的 `ticket` 查询参数，并先使用 WebDAV 管理凭据写入一次性 grant。外部 WebDAV 服务收到链接后，如果已有相同用户的 WebDAV session，就直接新增或刷新路径授权；否则生成短期 state Cookie，跳转到 OpenList 的授权页面。OpenList 前端用当前登录态调用 `/api/webdav/authorize`，把 state 写回 grant，随后浏览器返回 WebDAV 完成 Cookie 建立。

配置项：`webdav_auth_secret` 是共享密钥，`webdav_auth_audience` 区分服务，`webdav_auth_ticket_ttl` 是秒数，默认 300。

ticket 格式为 `base64url(JSON payload).base64url(HMAC-SHA256(payload-part))`，payload 包含路径、用户、audience、签发/过期时间和随机 nonce。grant 在首次生成时没有 state，浏览器授权阶段会以相同 nonce 原子覆盖为带 state 的 grant。

外部服务应校验版本、签名、audience、时间、路径、state Cookie 和 grant 中的 state，并将 ticket 消费为自己的 session。Cookie、session 和路径授权文件必须由 WebDAV 认证服务独立维护，不能复用或修改 OpenList 登录状态文件。成功后返回不带 ticket 的干净 URL；后续长视频 Range 请求只依赖 WebDAV session，不再依赖短期 ticket。grant 只允许消费一次。

当前 OpenList 网页端登录态保存在 `localStorage` 的 JWT 中，而不是 HTTP Cookie，因此必须经过 `@webdav-auth` 前端授权页，不能让 Apache 直接把浏览器重定向到后端 API 并期待 API 自动获得 OpenList 登录态。

OpenList 登出时会使用凭据 A 向 `/webdav-auth/revocations/` 原子写入当前用户的
撤销标记。Apache 只读取该标记并拒绝创建时间早于撤销时间的 session；它仍然负责
维护和删除自己的 session 文件。JWT 自然过期时没有可靠的服务器端登出回调，仍由
WebDAV session TTL 和请求时过期检查兜底。

登录用户也可以调用认证接口 `POST /api/webdav/revoke`，让 OpenList 对所有启用
WebDAV ticket 的 storage 写入该用户的撤销标记。该操作撤销账户级全部 WebDAV
session，不只是当前浏览器中的 Cookie。
