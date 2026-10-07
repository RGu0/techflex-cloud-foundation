# 设备身份、证明与机构库存边界

RAY-554 R2（2026-10-07）说明现有公共机制；本库没有鞋垫设备组或机构库存
业务模型。本页不声明终端A登记、终端B增量下行或电量状态同步已经部署。

## 三种身份分别登记

| 本库类型 | 现有职责 | 不能由此推断 |
| --- | --- | --- |
| `ClientInstallation` | 软件安装实例UUID、tenant、注册时间和platform_hint；安装不拥有License | UUID或平台hint是可信物理设备证明 |
| `Terminal` | 操作工作站UUID、tenant、site_id和label | 工作站与某双鞋垫永久绑定 |
| `MeasurementDevice` | 物理仪器UUID、tenant、model及可选serial_hint | serial_hint或登记成功即完成硬件认证；已具有主从MAC/库存字段 |

源码见 [device_trust.py](../../src/techflex_cloud_foundation/device_trust.py)
中的上述数据类与 `DeviceTrustService.register_installation`、`register_terminal`、
`register_measurement_device`。登记接口与存储机制不替代业务机构授权、库存审批
或管理员权限检查；接入服务负责身份、tenant归属和操作许可，不能只凭MAC登记他人资产。

## 可信证明、绑定和租约分别选择

`DeviceAttestationProvider.attest` 是产品注入的证明接口。
`DeviceTrustService.bind_device` 接收 `InstallationPrincipal` 并校验身份声明版本，要求产品provider
返回 `PhysicalDeviceIdentity`；没有可信身份或仅回显platform UUID会拒绝。
MAC、RSSI、platform_hint、用户提交的编号及UUID均不能单独当作密码学证明。
见同文件 `DeviceIdentityClaim`、`PhysicalDeviceIdentity`、`bind_device`，
以及 [test_device_trust.py](../../tests/test_device_trust.py) 的真实机制测试。
调用前由接入层认证安装凭据取得可信principal；`bind_device`本身不重新校验凭据，
不得用客户端自行构造的principal替代认证。

证明/绑定是本库已有且仍有效的可选产品机制，不因为鞋垫库存策略而取消。
需要可信绑定的产品继续实现provider并调用该接口；鞋垫库存登记可由业务
ownership/permit/admin授权管理，不要求把MAC伪装成provider证明，也不能
以未调用绑定为由绕过其他产品已有安全要求。

`HardwareLeaseService` 是独立的显式租约服务，支持申请、续期、释放、过期
及同asset有效租约冲突保护。安装、终端或仪器登记不会自动创建独占租约。
鞋垫按机构库存现场共享，不要求永久终端绑定或默认使用本库租约；BLE连接
同一时刻的限制不是云端资产授权证明，也不能替代应用并发与权限策略。

## 留在业务接入层的设备组与库存

原业务线要求的一双鞋垫主节点MAC+从节点MAC、编号/尺码/固件、电量与时间、
可用/使用中/有未回传数据/停用状态及增量下行，不是 `MeasurementDevice`
已有字段。产品接入层须定义版本化设备组身份、登记去重、机构ownership与许可、
管理员/终端操作权限、观测字段和状态权威来源，以及revision/增量分页/删除和
冲突语义。本页不制定尚未确认的wire字段、状态优先级或新增公共metadata API。

应用不可把一次BLE连接或电量观测自动解释为库存启用、所有权迁移、可信证明
或终端绑定。停用授权与设备观测分别核验，原始MAC与身份材料的保存和读取
范围遵循业务政策；本库不内置设备组、编号/尺码或电量metadata。

## 真实部署联调待验

1. 终端A在有权机构登记设备组，终端B通过真实增量接口看到正确编号与尺码。
2. 实际电量/状态上报后其他终端可见；跨机构读取与未授权登记拒绝。
3. 共享设备跨终端使用、登记冲突、状态变化与增量恢复按已确认业务协议验收；
   不把本库内存store成功当成HTTP/数据库持久化或移动同步成功。
4. 记录业务部署/客户端修订、授权前提和脱敏结果；上述联调在本scope交付时
   仍未完成，本库R2指南完成不替代它。

参见 [智能鞋垫产品接入契约](insole-product-contract.md)、
[License与生命周期](license-and-lifecycle.md)、[API Reference](../api-reference.md)。
