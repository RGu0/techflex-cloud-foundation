# 智能鞋垫产品接入契约（RAY-551）

本页记录已确认的产品要求和基础库/应用边界。2026-10-07 用户确认
将 foundation 契约交付与业务部署联调分开记录（RAY-551 R2）。
本页不代表已部署的产品注册；本库范围完成也不代表业务 integration
验收通过，后者保留下面的独立清单。

## 产品事实与交付位置

| 项目 | 接入要求 | 实现责任 |
| --- | --- | --- |
| 产品标识 | 智能鞋垫使用独立标识，不复用 FeetForcePlate 产品 | 服务部署的产品目录与业务路由 |
| Token audience | 鞋垫独立 audience；足压板凭据不能跨产品使用 | 应用令牌签发与验证配置 |
| 平台 | 支持 `ios`、`android`，保留足压板的桌面平台 | 业务 `SystemSummary` DTO 与平台校验 |
| 设备组 | 主节点 MAC + 从节点 MAC；一双鞋垫归属于机构 | 产品身份解析、库存与硬件证明适配 |
| Payload | `insole-session-archive/1` | 业务 payload/schema 注册与接收适配 |
| 归档 | 会话收尾后确定性 tar.gz，以 4 MiB 切件；末件可更小 | 产品客户端归档与云端接收 |

`product_registry.ProductRecord` 和 `ProductCatalog` 接受部署注入的
产品及版本事实，基础库不内置足压板或鞋垫专属业务规则。只调用
注册库不意味着 HTTP 服务的身份、平台、audience 或 schema 校验
已经支持鞋垫。

具体产品标识、audience 字符串及 tar.gz 内容布局由应用的版本化契约
登记；本页不虚构尚未发布的字段值。必须使用真实支持的 schema
集合，不能用注册表声明代替解析实现。

## 设备与终端边界

主从 MAC 是产品设备组的登记标识，不是密码学认证证明。
`DeviceAttestationProvider` 由产品接入层提供可信证明；平台 UUID、
RSSI 及单纯回显 MAC 不能替代它。

机构拥有鞋垫库存；工作人员在会话开始前选择合适的一双。设备不
永久绑定某台终端，也不要求沿用足压板的一账号一硬件在线租约。
机构多终端激活、凭据吊销及席位授权属于 RAY-552，设备库存同步
属于 RAY-554；产品注册不得绕过这些权限边界。

## 上传边界

鞋垫采用收尾后的归档上传，而不是足压板按采集帧实时切分及密封
的业务格式。复用通用幂等/续传机制时，仍须使用产品自身的 DTO、
元数据和完成规则。

应用 HTTP 接口的完成状态 `INGESTED` 与基础库 `SessionState.COMPLETED`
不是可直接替换的 wire 字段；由产品适配层明确映射并验证。

2026-10-07，RAY-515 的分块摘要比较、可选重试抖动和应用上传编排
契约，以及 RAY-540 的内容校验已合并，并包含在
[v0.4.0](https://github.com/RGu0/techflex-cloud-foundation/releases/tag/v0.4.0)。
消费者仍须升级并验证自己的对象/会话适配器，不能以库发布代替接入验收。

多条目或多切件清单声明 `annotations.ingestion_mapping="entry-parts/1"`；
按条目顺序展开条目局部切件为上传全局槽位，不能直接把局部索引当全局索引。
对象适配器提供流式 `read_chunks`，会话适配器提供对已验证切件快照的
原子 `finalize`；应用保证校验到提交期间对象不被删除或替换。
只有清单摘要匹配且带 `verification_version="content/1"` 的回执
才可通过 `ResumeDriver.may_retire_local`。历史缺少该字段或未知版本的
回执不自动升级；消费者须保留本地字节，不能凭 HTTP 成功或切件确认退休数据。
详见[内容验证与迁移](ingestion-content-verification.md)、
[可执行通用向量](../contracts/ingestion-content-vectors.json)和
[可靠上传](reliable-upload.md)。

## 集成验收清单

1. 在真实 integration 部署登记鞋垫产品，使用该产品的有效终端
   凭据完成创建会话、上传归档分段、完成并达到 `INGESTED`。
2. 验证 iOS/Android 的身份与平台声明被接受，错误产品、audience
   和未知 schema 被拒绝；足压板已有身份与桌面平台回归通过。
3. 核对服务端接收字节、归档内容与最终回执，断网重试不丢失本地
   未确认数据。成功的基础库内存测试不能代替真实服务验收。
4. 发布可被 Dart 消费的 OpenAPI、错误码和一致性向量（RAY-556），
   并记录部署版本、产品注册事实和不含凭据的验收证据。

本库 scope 交付通用接入边界和文档，不新增产品业务 API。
业务服务实现和真实 integration 证据由相应仓库的合法交付承接；
按 R2 记录的本库完成状态不能替代该业务线验收。

## 来源

- [RAY-551](https://linear.app/ruiguo/issue/RAY-551)：当前产品要求与验收。
- gait-insole-flutter 共享 `documents/06-云端接口与同步-Spec.md`
  §3.3、§5、§6：设备共享、归档切件及云端接入缺口。
- `src/techflex_cloud_foundation/product_registry.py`、`device_trust.py`
  及 `gateway.py`：部署注入产品事实、可信硬件证明与业务路由边界。
