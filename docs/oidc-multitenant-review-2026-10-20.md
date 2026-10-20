# OIDC 单进程多租户功能审查报告

- 审查日期：2026-10-20
- 审查对象：`work` 分支，基线提交 `2b62f6663`
- 审查方式：静态代码审查、现有测试与部署文档核对
- 审查范围：OIDC 网关、租户路由、连接配置准入、服务端共享状态、浏览器切号与验证覆盖

## 结论

OIDC 网关完成了授权码与 PKCE 登录、ID token 校验、随机会话和租户键转发；后端按租户创建独立的数据目录、`WebState` 与连接状态，浏览器切号时也会清理主要的本地缓存。这些是多账号功能的基础。

当前仍存在一项高优先级的本地文件访问限制绕过，以及两项跨租户共享状态或功能封锁问题。**在修复并完成真实双账号验证前，不建议把该模式作为面向互不信任用户的生产隔离方案。** 本报告没有证明任意文件内容可直接通过 API 下载，也没有进行运行时渗透测试。

| 编号 | 优先级 | 问题 | 主要影响 |
| --- | --- | --- | --- |
| MT-01 | P1 | MQTT 嵌套证书路径绕过连接配置校验 | 已登录账号可令服务进程打开本地证书或私钥文件 |
| MT-02 | P2 | Nacos 搜索取消表没有租户作用域 | 知道相同操作 ID 的账号可取消其他租户的操作；相同 ID 相互占用 |
| MT-03 | P2 | 文件接口封锁列表遗漏，MongoDB 来源表为进程全局 | 文档承诺的 403 边界不一致；一个租户可占用共享来源容量 |
| MT-04 | 验证缺口 | 双账号后端测试默认跳过 | 目前无法凭现有常规测试确认完整部署链路的隔离效果 |

优先级含义：P1 应在开放多租户服务前修复；P2 应在宣称租户间操作隔离及功能边界前修复。

## 已确认的隔离措施

1. 网关以经过签名、签发方、受众、有效期及 `nonce` 校验的 ID token 的 `(iss, sub)` 生成租户键；会话标识保存在网关内存中。见 `scripts/oidc-multitenant.mjs:19-46,185-220`。
2. 网关向只监听回环地址的后端注入随机内部密钥和租户键；后端检查这两个请求头，然后按租户键懒加载独立路由及 `WebState`。见 `scripts/oidc-multitenant.mjs:145-159,213-224` 和 `crates/dbx-web/src/main.rs:1569-1654`。
3. 租户数据写入 `DBX_DATA_DIR/tenants/<租户键>`，各自打开 `dbx.db` 并创建连接状态。见 `crates/dbx-web/src/main.rs:1522-1567,1600-1622`。
4. 前端在加载主工作台前校验账号，并在租户变化时清理 `localStorage` 和三个已知 IndexedDB 数据库。见 `apps/desktop/src/StartupGate.vue:69-95` 和 `apps/desktop/src/lib/startup/tenantBrowserIsolation.ts:1-30`。

这些措施保证了主要存储与路由按账号分离，但不能自动隔离进程全局静态表或服务进程的文件权限。

## 问题详情

### MT-01：MQTT 嵌套证书路径绕过本地文件限制（P1）

**证据。** `safe_multitenant_connection` 允许 `db_type = "mqtt"`，并只检查顶层 `ca_cert_path`、`client_cert_path`、`client_key_path` 等字段；它没有检查 `external_config`。见 `crates/dbx-web/src/main.rs:1488-1512`。MQTT 的实际配置从 `external_config` 解析，证书认证使用 `auth.caCertPath`、`auth.clientCertPath`、`auth.clientKeyPath`。见 `crates/dbx-types/src/mqtt.rs:27-42,135-151`。建立连接时，这些路径会交给 `File::open`，以 `dbx-web` 的系统身份读取。见 `crates/dbx-core/src/admin/mqtt/client.rs:1339-1387`。默认 `dbx-web` 构建启用 `mq-admin`，见 `crates/dbx-web/Cargo.toml:12-15`。

**可达路径。** 已认证账号可向 `/api/connection/test` 或 `/api/connection/connect` 提交顶层合法的 MQTT 配置，同时把本地绝对路径放在 `external_config.auth` 中。入口校验会放行；连接实现随后尝试打开该路径。证书或私钥须能被相应解析器接受，才能继续用于 TLS 连接；即使解析失败，打开文件的行为也已经越过了文档中的本地路径禁令。

**建议。** 在后端对允许的每种 `db_type` 解析完整的强类型配置并验证所有本地路径。对于多租户 MQTT，可先拒绝 `auth.kind = "certificate"`，待支持受控的证书材料输入方式后再开放。测试应覆盖 `/api/connection/save`、`test`、`test-info`、`connect` 和 `mcp/add` 的相同策略，并包含嵌套路径样例。

### MT-02：Nacos 搜索取消操作可跨租户命中（P2）

**证据。** `/api/nacos/configs/search/cancel` 在多租户模式下未封锁，其处理器只接受 `operation_id`，没有读取 `WebState` 或租户键。见 `crates/dbx-web/src/main.rs:1088-1090`、`crates/dbx-web/src/routes/nacos.rs:701-704`。核心搜索的 `OPERATIONS` 是进程全局 `HashMap<String, CancellationToken>`；开始、取消和结束操作均只按客户端提供的 ID 查找。见 `crates/dbx-core/src/admin/nacos/search.rs:19-53,77-81`。

**影响。** 两个租户使用相同操作 ID 时，后启动者会收到“已运行”错误；拥有该 ID 的另一个租户还能取消先启动者的搜索。随机生成且不泄露的 ID 降低了偶然或盲猜风险，但不能构成租户授权检查。

**建议。** 把取消表放入租户独立的 `WebState`，或将 `(tenant_key, operation_id)` 作为键，并要求取消请求在同一租户上下文中查找。增加两个租户使用相同 ID 的并发和取消测试。

### MT-03：文件接口封锁不完整，MongoDB 来源表跨租户共享（P2）

**证据。** `blocked_multitenant_path` 封锁 `/api/import`、`/api/export`、`/api/sql-file` 等前缀，但未包含 `/api/nacos/configs/import/*`、`/api/nacos/configs/export` 与 `/api/mongo/dump/source`。见 `crates/dbx-web/src/main.rs:1479-1486,1090-1092,1202-1215`。Nacos 属于多租户允许的连接类型，相关导入导出处理器会在该租户目录下写入、读取 ZIP 文件。见 `crates/dbx-web/src/routes/nacos.rs:707-800`。MongoDB 连接类型未被准入，但其 dump 来源准备接口本身不要求连接，可在租户临时目录接受上传；准备结果存入进程全局 `SOURCES`，全进程容量为 32 项。见 `crates/dbx-web/src/routes/mongodb_dump.rs:58-66,88-96` 和 `crates/dbx-core/src/data/mongodb_dump/source.rs:30-33,96-109`。

**影响。** 当前行为与部署文档“服务器文件导入导出相关 API 返回 403”的描述不一致。Nacos 的文件操作仍受各租户数据目录约束，现有证据不表明它可直接读取其他租户文件。MongoDB 来源表则确实共享容量：一个租户持有足够多的有效预览来源时，其他租户也会遇到容量错误。

**建议。** 为多租户模式维护明确的 API 允许清单或能力分组，避免新路由默认进入可访问面。若保留 Nacos 包导入导出，应改正文档并评估文件大小与配额；若承诺禁用文件功能，应一并封锁。MongoDB dump 来源接口应封锁，或者将来源表、容量和释放操作全部按租户划分。

## 验证缺口与建议验收

`scripts/oidc-multitenant.test.mjs` 主要覆盖 token 身份、伪造请求头和两个账号的网关转发；`scripts/oidc-multitenant.shared.test.mjs:9` 只有设置 `DBX_TEST_WEB_BIN` 才会运行真实后端测试，而且目前仅检查两个账号的连接配置分离、几个封锁路径及迁移流程。仓库文档也明确记录完整构建和双账号端到端隔离尚未完成。此次报告没有运行测试、构建或启动前后端。

修复后的验收至少应覆盖：

1. 使用默认发布特性的 `dbx-web`，验证 MQTT 嵌套证书路径在所有连接入口返回 403，且服务进程没有打开指定文件。
2. 让两个真实租户同时使用相同 Nacos 搜索 ID，确认互不冲突且不能互相取消。
3. 枚举所有 Web API 路由，对多租户能力策略做自动对照；明确 Nacos 与 MongoDB 文件接口的预期状态。
4. 在同一个后端进程中验证两个账号的连接、凭据、查询任务、临时文件、浏览器切号与登出流程，并用真实身份提供方完成登录回调测试。

## 已知设计限制

`DBX_MAX_ACTIVE_TENANTS` 默认上限为 32，目前租户状态只增加、不回收；达到上限后新账号 API 返回 503。这是现有文档已披露的容量限制，不列为本次新发现的代码缺陷。单进程仍共享操作系统身份和网络权限，修复上述问题也不会提供进程或容器级隔离。
