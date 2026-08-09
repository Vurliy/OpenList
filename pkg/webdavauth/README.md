# OpenList WebDAV ticket

开启 `webdav_auth_enabled` 后，OpenList 在直接 WebDAV 链接中追加 `ticket` 查询参数。外部 WebDAV 认证服务使用同一 HMAC 密钥校验 ticket，并将通过校验的路径绑定到自己维护的 cookie/session。

配置项：`webdav_auth_secret` 是共享密钥，`webdav_auth_audience` 区分服务，`webdav_auth_ticket_ttl` 是秒数，默认 300。

ticket 格式为 `base64url(JSON payload).base64url(HMAC-SHA256(payload-part))`，payload 包含路径、用户、audience、签发/过期时间和随机 nonce。

外部服务应校验版本、签名、audience、时间和路径，并将 ticket 消费为自己的 session/grant。cookie、session 和路径授权文件必须由 WebDAV 认证服务独立维护，不能复用或修改 OpenList 登录状态文件。建议校验后跳转到不带 ticket 的干净 URL，并按 nonce 防止重复使用。
