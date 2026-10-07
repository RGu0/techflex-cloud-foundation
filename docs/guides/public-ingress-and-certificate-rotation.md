# 正式入口与证书轮换验收

RAY-558 R2（2026-10-07）记录本库入口契约与验收方法。实际部署、
移动默认信任连接和证书轮换执行须分别取得证据；本指南不宣称这些联调已完成。

## 已有入口及日期事实

复用现有 `https://api.gu0.tech`，不新建公网入口。

| 观察日期 | 已取得事实 | 不能由此推断 |
| --- | --- | --- |
| 2026-09-07 | RAY-404 部署记录：域名解析至既有服务器；nginx 443；Let's Encrypt ECC 证书；系统公有信任库 TLS1.3 握手；根路径返回404及 correlation id | iOS/Android 默认配置可连接；证书续期已执行 |
| 2026-10-07 | 只读 OpenSSL 探测连接443，公有链 Let's Encrypt YE1 / ISRG 验证返回0，TLS1.3；叶证书 CN 为 api.gu0.tech，有效期2026-09-07 02:51:15Z至2026-12-06 02:51:14Z | 桌面探针等于移动系统信任；HTTP业务接口正常 |
| 2026-10-07 | curl根路径探测出现 connection reset；经过代理与绕过代理的尝试均未取得成功HTTP响应 | 已定位服务端原因；创建/上传/完成可用 |

历史依据在本项目共享证据
`evidence/ray-404/production-acceptance/debug/2026-09-07-integration-probe.md`
补充3、同目录 `2026-09-07-deployment-inventory.md`，以及
`runbook/production-acceptance-runbook.md` §1.6。
本轮原始探测与验收结论存于
`evidence/ray-558/public-ingress-contract/acceptance/`。
TLS握手和HTTP响应分别记录；HTTP失败保留为待定位事实，不关闭证书验证来重试。

## Foundation 配置边界

- `parse_deployment_profile` 对 `environment=production` 强制 HTTPS、
  hostname、公有 CA 声明及443；IP、私有CA、非443均拒绝。
  `tests/test_platform_config.py` 覆盖这些负例。声明通过仍须真实网络验证。
- `SecureTransport` 默认公有信任，拒绝 `CERT_NONE`、关闭hostname验证
  或布尔verify；`tests/test_transport.py` 覆盖约束。应用必须注入实际生产URL。
- 包内 `load_default_cloud_config()` 仍为既有 integration IP:7443/私有CA。
  它不自动升级到production，不能把该私有CA包用于生产信任。
  见 [Cloud Access & Default Configuration](cloud-access-and-default-config.md)。
- 不修改integration默认、生产机器、移动工程或公共API。历史部署库存曾记录
  应用 PUBLIC_BASE_URL 仍为integration；实际应用URL是否已切换须另验。

## 只读预检与待验记录

由部署操作者在批准环境取得以下独立记录；本库不执行SSH或改配置：

1. 记录探测时间、目标URL、DNS结果、443连通、SNI及hostname验证结果，
   保存公有默认信任链、SAN、issuer、serial和有效期。记录所用工具与信任库；
   不将单纯CN文本或未开启hostname验证的链校验当作SAN验证。
2. 对已批准的无凭据HTTP检查路径记录状态码和 correlation id；根路径404可作
   网关可达观察，不能当业务健康。连接reset、超时和TLS错误分别留原始结果，
   先查监听/上游/访问日志/网络路径，不关闭验证、不上传凭据。
3. 操作者只读核对现有acme.sh签发配置、续期调度与最近执行记录、nginx引用的
   证书文件及reload钩子；不把存在cron当作续期成功。秘密、私钥、token及环境
   变量完整转储不进入本库或共享证据。

## 现有轮换方案及执行验收

2026-09-07记录的方案是acme.sh + Let's Encrypt HTTP-01、cron/ARI续期和
nginx reload钩子，预计当时下一次续期约2026-11-06。该预计时间不是执行证据。

操作者执行前，核对现行域名控制权、HTTP-01所需路径/端口、签发限制、受保护的
证书安装位置、完整链及reload钩子；记录旧serial/有效期和当前HTTP探测结果。
按现有部署runbook运行获准的续期/安装流程，验证证书与私钥匹配、SAN覆盖域名，
先通过nginx配置检查，再reload并从外部重新探测实际提供的证书。这里描述的是
待执行步骤，不提供自动远程变更或盲目强制续期脚本。

执行记录必须包含：操作者/批准依据、部署修订、时间、签发/安装/配置检查/reload
各自结果、更新前后serial与有效期、外部公有信任验证及HTTP连续性结果。
有失败就保留原证据，不能用成功的签发掩盖安装或reload失败。

失败处理：签发/验证/配置检查失败时保留仍有效的已部署证书，停止切换并通知部署
负责人；reload失败核查进程与日志，使用已验证的既有配置恢复流程。到期监测与
续期失败告警须由部署侧实际启用，并记录通知对象、检测频率/提前窗口及告警演练
结果；本库不虚构这些值或声称监控已上线。已过期证书不得靠关闭TLS验证绕过。

## 移动默认信任与应用接入待验

| 待验项 | 必须记录的真实证据 |
| --- | --- |
| iOS | OS/设备或模拟器、应用修订与构建类型、实际URL；默认ATS和系统信任、无私CA注入/不安全例外下的连接结果 |
| Android | OS/设备、应用修订与release构建、实际URL及联网权限；默认系统信任、无debug CA/user CA例外或绕过验证下的连接结果 |
| 应用配置 | 实际使用已有正式URL；integration配置不能冒充production配置 |
| HTTP及业务 | 连接结果与业务授权分开；有权的真实业务联调另记，不把HTTP200或TLS握手当上传完成 |
| 轮换连续性 | 真实轮换后两平台再次默认信任连接，记录失败与恢复，不用桌面OpenSSL替代 |

上述移动/部署联调在2026-10-07本scope交付时仍待验。本scope的文档与观察证据
验收、合并和R2完成回执，不替代这些真实联调要求；不得据此宣称生产业务可用。
