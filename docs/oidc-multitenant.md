# OIDC 单进程多账号部署

`scripts/oidc-multitenant.mjs` 处理 OpenID Connect 登录，单个 `dbx-web` 后端进程处理所有已登录账号。无需 Docker、镜像或每账号一个服务进程。网关验证 ID token 的签名、签发方、受众、有效期和 nonce，然后以 `(iss, sub)` 作为账号身份；邮箱和显示名称不参与身份判断。

后端按账号懒加载独立的 `WebState`，因此每个账号有各自的 SQLite 文件、加密密钥、连接池、临时凭据、查询任务和运行状态。数据位于 `DBX_DATA_DIR/tenants/<sha256(iss + NUL + sub)>`。网关给后端发送随机内部密钥及账号键；后端只监听 `127.0.0.1`，没有正确内部密钥的请求会被拒绝。前端切换账号时会清理浏览器本地缓存。

## 准备

1. 安装 Node.js 22.13 或更新版本，运行 `pnpm install --frozen-lockfile && pnpm build`，再运行 `cargo build --locked --release -p dbx-web`。这会生成前端 `dist/` 和后端 `target/release/dbx-web`。
2. 在身份提供方注册一个 **confidential** OIDC 客户端，启用授权码流程。把精确的回调地址注册为 `https://dbx.example.com/api/auth/oidc/callback`。提供方需支持 `client_secret_basic`，并用 RSA 或 P-256 密钥签发 `RS256`、`PS256` 或 `ES256` 的 ID token。
3. 用专用的非 root 用户启动网关。只通过 HTTPS 反向代理公开网关；不要公开后端端口。确保数据目录只对该服务用户可写，并备份每个账号的数据目录及密钥。

```bash
export DBX_OIDC_ISSUER='https://identity.example.com/realms/my-realm'
export DBX_OIDC_CLIENT_ID='dbx-web'
export DBX_OIDC_CLIENT_SECRET='从密钥管理器注入'
export DBX_OIDC_REDIRECT_URI='https://dbx.example.com/api/auth/oidc/callback'
export DBX_DATA_DIR='/var/lib/dbx-multitenant'
export DBX_STATIC_DIR='/path/to/dbx/dist'
export DBX_WEB_BIN='/path/to/dbx/target/release/dbx-web'
export DBX_BIND_ADDR='127.0.0.1'
export DBX_PORT='4224'
node scripts/oidc-multitenant.mjs
```

`DBX_MAX_ACTIVE_TENANTS` 默认为 32。后端只在账号第一次访问 API 时打开其数据库和连接池，目前没有空闲回收；达到上限时新账号的 API 返回 503。重启网关会使内存中的浏览器会话失效。旧版单用户数据不会自动归属给先登录的人，需要明确选择账号后迁移。

## 多租户模式的功能边界

单进程模式共享操作系统身份，不能像独立操作系统沙箱那样抵御后端代码执行漏洞。因此多租户入口只允许内置的远程数据库驱动；拒绝 SQLite、DuckDB、外部驱动/agent、插件、SSH 隧道、服务器本地证书路径和初始化脚本。插件、AI、服务器文件导入导出、文档文件、云同步及 MCP 等相关 API 在此模式下返回 403。现有单用户 `dbx-web` 启动方式不受这些限制。

这些限制用于阻止已知的服务端本地文件访问入口，不能证明所有第三方数据库或依赖都没有类似能力。面向互不信任的公网用户时，应限制服务账号的宿主机文件权限，并用网络出口策略限制它能连接的地址。若需要保留插件、本地文件数据库或抵御后端远程代码执行，必须使用进程/操作系统级隔离；单进程不具备这种安全边界。

用 `node --test scripts/oidc-multitenant.test.mjs` 验证 OIDC 协议逻辑。构建后端后，设置 `DBX_TEST_WEB_BIN=/path/to/dbx-web` 并运行 `node --test scripts/oidc-multitenant.shared.test.mjs`，可用模拟身份提供方验证两个账号的后端数据隔离。上线前仍需用真实身份提供方完成登录测试。
