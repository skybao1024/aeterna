# Aeterna v4.0 — 产品与架构设计文档

> 状态：可进入技术原型阶段  
> 更新日期：2026-09-16  
> 文档范围：Windows/macOS 桌面端、本地保险箱、设备活动心跳、云端通知与延迟紧急恢复

## 1. 项目定义

Aeterna 是一个 Local-First 的桌面端数字遗产工具。桌面客户端开源，以便用户和安全研究者核验本地数据边界、加密实现和网络行为；官方托管的 Aeterna Control Plane 不属于客户端开源范围。客户端在用户设备上加密保存留言、影像、账号说明和其他交接资料，通过本机活动检测判断已绑定设备是否仍被使用，并由独立通知服务在所有设备长期没有活动后执行预警、宽限和联系人通知。

Aeterna 不是死亡证明系统。它只能够判断：

> 在设定期限内，没有任何有效且未撤销的设备报告可接受的用户活动。

系统不生成遗嘱，不判断留言的法律效力，不接入 AI，也不向 Aeterna 服务端上传保险箱、留言、影像或附件内容。

### 1.1 核心价值

- 日常资料保存在本地，并以强加密保护。
- 用户无需定期打开 Aeterna 或手动签到。
- 多台设备中的任意一台出现有效活动，都可以延后账户的不活跃期限。
- 主密码永不上传。
- 联系人不需要知道主密码，而是使用延迟生效的紧急恢复码。
- 服务端单独持有的数据不足以解密本地保险箱。
- 最终恢复仍然要求联系人取得一台保存资料且可进入操作系统的设备。

### 1.2 明确不做

- 不证明用户已经死亡、失能或仍然存活。
- 不监控浏览器 URL、应用内容、按键内容、鼠标位置或窗口标题。
- v1 不提供设备间实时同步。
- v1 不提供 Aeterna 云端保险箱备份。
- 不生成遗嘱或其他法律文书。
- 不接入 LLM，不保存第三方 AI API Key。
- 不绕过 Windows/macOS 登录、BitLocker、FileVault 或其他全盘加密。
- 不承诺永久可用、绝对准时或“数学上绝对安全”。

### 1.3 Release sequencing

The first production desktop release is macOS-only. Platform-neutral vault,
protocol, and control-plane work may proceed after the macOS Phase 0 gate, but
that gate does not qualify, advertise, or authorize a Windows release.

G0 accepts Apple Silicon macOS 15.0 as the initial product and test floor.
Current real-machine activity, Keychain, and Argon2 evidence covers macOS 26.3
only; the configured macOS 15 CI job has not run for the Phase 0 checkpoint.
I08 must complete the native activity, lifecycle, secure-storage, and
KDF matrix on an updated macOS 15 host and on the then-current macOS release
before Aeterna makes that support claim. If the floor cannot pass, it must be
raised to the oldest fully verified major version.

The Windows implementation remains a risk-prototype checkpoint until a real
interactive supported Windows host completes the activity, Credential Manager,
autostart, local/remote-session, lifecycle, and cleanup matrices. Windows keeps
its original acceptance criteria and has a separate qualification gate before
any Windows production hardening, packaging, support claim, or release.

## 2. 角色与核心术语

| 术语              | 含义                                                          |
| :---------------- | :------------------------------------------------------------ |
| Owner             | 创建并维护保险箱的用户                                        |
| Contact           | Owner 指定的通知联系人                                        |
| Recovery Contact  | 被授权在最终释放后执行紧急恢复的联系人                        |
| Device            | 已绑定账户、能够提交活动心跳的电脑                            |
| Vault             | 某台设备上的本地加密保险箱                                    |
| MP                | Master Password，Owner 日常使用的主密码                       |
| ERC               | Emergency Recovery Code，系统随机生成的紧急恢复码             |
| VDK               | Vault Data Key，随机生成的保险箱数据密钥                      |
| SRS               | Server Release Secret，服务端保存、最终释放后才提供的随机因子 |
| Inactivity Window | 从最后一次有效心跳开始计算的不活跃期限                        |
| Warning Window    | 到期前向 Owner 发出预警的时间段                               |
| Grace Period      | 到期后、最终通知和密钥因子释放前的宽限期                      |

## 3. 产品保证与信任边界

### 3.1 Aeterna 可以保证

- 保险箱内容在写入持久化存储前完成本地加密。
- 主密码、ERC、VDK 不上传服务端。
- 服务端数据库单独泄露时，攻击者不能仅凭服务端数据解密保险箱。
- 除经过单独认证和冷静期的 Owner 自助恢复外，ERC 在服务端正式释放 SRS 以前，不能通过正常或修改后的本地客户端独立解开 VDK。
- 服务端使用自己的接收时间计算心跳和期限，不信任客户端系统时间。
- 最终释放前存在强制 Owner 预警和宽限期。

### 3.2 Aeterna 不能保证

- 活动设备的操作者一定是 Owner 本人。
- 已被恶意软件控制或已经解锁的操作系统仍然安全。
- 掌握电脑登录密码的人不会访问 Aeterna 以外的本地文件。
- 电脑损坏、磁盘损坏且无其他本地副本时仍能恢复资料。
- 邮件、短信和网络服务永远可达。
- 联系人邮箱或手机号永远有效。
- SRS 一旦正式释放，系统无法保证收回已经获得的解密能力。

## 4. 总体架构

```text
┌──────────────────────── Owner Device ────────────────────────┐
│                                                              │
│  React UI ──窄 IPC── Rust Core                               │
│                       ├─ Vault Engine                        │
│                       ├─ Activity Agent                      │
│                       ├─ Heartbeat Client                    │
│                       ├─ Recovery Client                     │
│                       └─ Backup Import / Export               │
│                                                              │
│  SQLite / encrypted attachments      OS Credential Store     │
│  （只保存密文和必要元数据）          （设备私钥、会话令牌） │
└──────────────────────────┬───────────────────────────────────┘
                           │ TLS + signed requests
                           ▼
┌──────────── Aeterna Control Plane (hosted service) ───────────┐
│ Account / Device / Policy / Heartbeat State                   │
│ Warning + Grace + Release State Machine                       │
│ Encrypted SRS / Contacts / Notification Templates            │
│ Transactional Outbox / Email / SMS / Payment                  │
└──────────────────────────┬───────────────────────────────────┘
                           │ final notification + claim link
                           ▼
                    Recovery Contact
                           │
                           └─ 取得电脑和 ERC 后在本地恢复
```

### 4.1 本地与云端数据边界

| 数据                         |         本地         | Aeterna 服务端 |
| :--------------------------- | :------------------: | :------------: |
| 主密码 MP                    |          是          |       否       |
| 紧急恢复码 ERC               |  是/由用户线下保管   |       否       |
| 保险箱内容、留言、影像、附件 |          是          |       否       |
| VDK                          |  仅以被包裹形式保存  |       否       |
| SRS                          | 设置时仅短暂进入内存 |    加密保存    |
| 设备 ID、公钥、最后心跳      |          是          |       是       |
| 不活跃策略和状态             |         缓存         |       是       |
| 联系人邮箱、手机号           |     可缓存且加密     | 是，字段级加密 |
| 通知内容和位置说明           |     可缓存且加密     | 是，字段级加密 |
| 支付和短信额度               |          否          |       是       |

服务端能够在发送时读取联系人地址和通知正文，因此通知数据不是端到端零知识数据。产品只能承诺保险箱内容不上传，不能宣称服务端不接触任何个人信息。

## 5. 核心用户流程

### 5.1 首次设置

1. Owner 验证邮箱并创建账户。
2. 应用生成设备密钥对并注册设备。
3. Owner 设置主密码。
4. 应用生成 VDK 并创建本地保险箱。
5. 应用随机生成 ERC，要求 Owner 打印、抄写或保存到 U 盘。
6. 服务端为该设备生成 SRS；应用建立延迟恢复包装后立即清理内存中的 SRS。
7. Owner 设置不活跃期限、联系人和通知内容。
8. Recovery Contact 完成邮箱验证或明确同意接收。
9. Owner 选择 ERC 和电脑访问凭据的保管方式。
10. 应用检查自启动和活动检测能力，提交首次有效心跳。

### 5.2 两种凭据保管方式

#### A. 高度信任模式

Owner 直接把以下内容交给亲近之人：

- 电脑登录方式；
- ERC；
- 资料所在设备和基本操作说明。

ERC 在最终释放以前不能走联系人恢复流程，但电脑密码可能允许联系人提前访问 Aeterna 之外的数据。如果 Owner 邮箱已经登录在该电脑上，联系人还可能尝试冒充 Owner 发起自助恢复；UI 必须明确提示高度信任模式不提供对该联系人的强对抗保证。

#### B. 密封保管模式

Owner 将以下内容保存到纸张、U 盘、保险柜或密封信封：

- 电脑登录方式或磁盘恢复方式；
- ERC；
- 设备位置；
- 简短恢复说明。

云端通知只说明去哪里取得这些内容，不包含任何密码或 ERC。

### 5.3 日常运行

- 应用随目标用户登录系统后在后台启动。
- 单纯开机、启动应用或设备唤醒不构成有效活动。
- After unlock or long idle, valid activity requires two HID-class interactive
  input epochs separated by a successful unlock-gate check; Combined-only input
  does not count. HID-class interaction may originate from the local console or
  an authenticated remote login, both of which count as user activity.
- 客户端提交签名心跳；服务端以接收时间更新账户期限。
- 用户不需要打开 Aeterna，也不需要定期手动确认。

### 5.4 最终恢复

1. 所有设备超过不活跃期限。
2. 服务端向 Owner 发送预警并进入宽限期。
3. 宽限期内未收到有效心跳，状态变为 `RELEASED`。
4. 服务端通知 Recovery Contact，并提供一次性领取链接。
5. 联系人根据通知取得电脑、系统访问方式和 ERC。
6. 联系人在本地 Aeterna 中进入“紧急恢复”。
7. 联系人通过通知链接和邮箱 OTP 取得短期 Claim Token。
8. 本地应用使用 Claim Token 向服务端领取该设备对应的 SRS。
9. 应用使用 ERC + SRS 解开本地 VDK，展示保险箱内容。

## 6. Activity detection and heartbeat

### 6.1 Valid activity

Valid activity must satisfy all of the following:

- it occurs in the target login session where Aeterna is installed;
- the session is active and the platform-specific unlock gate succeeds without
  user interaction;
- two distinct HID-class interactive input epochs are observed, with a successful
  unlock-gate check after the first epoch and before the second;
- the device remains validly bound; and
- the device signs the heartbeat and the service accepts it.

On macOS, Aeterna classifies input by sampling both Quartz
`HIDSystemState` and `CombinedSessionState`. A new HID epoch is eligible as
interactive activity, whether posted by the local console or an authenticated
remote login. A Combined-only epoch, including synthetic or other session
input that does not also advance HID state, is suppressed by default and clears
any pending confirmation.

The I01 target-host matrix demonstrated that macOS Screen Sharing input advances
both Quartz state tables. On 2026-09-21 the user explicitly confirmed the
product semantic that remote login is valid activity. Quartz HID age is not
described as proof of local physical presence.

### 6.2 Events that do not count as activity

- operating-system or Aeterna startup;
- the device merely being online;
- background work or system updates;
- screen wake or system wake by itself;
- background application startup;
- session switching without later confirmed HID-class input;
- login-screen credential input;
- a single unconfirmed HID-class input epoch;
- Combined-only remote or synthetic input; or
- replay of an old activity record.

### 6.3 Event algorithm

The defaults below may be changed by remote configuration, but configuration
cannot bypass the privacy and input-source boundaries:

```text
Application startup:
  Establish gate and input baselines. Do not submit a heartbeat.

Lock, sleep, switch-out, gate failure, or invalid sample:
  Clear every pending activity confirmation and fail closed.

Verified unlock:
  When the Keychain gate first becomes accessible, establish new HID and
  Combined baselines. This discards credential input observed at the login
  screen.

Post-unlock input:
  Within 2 minutes, the first new HID epoch arms a candidate. A second distinct
  HID epoch confirms it only if an intervening gate check succeeded.

Idle recovery:
  After HID idle time >= 30 minutes, the first new HID epoch arms a candidate
  and the second distinct HID epoch confirms it.

Continuous use:
  While the gate remains accessible and HID activity continues, arm a refresh
  every 4 hours and require the same second-epoch confirmation.

Combined-only input:
  Suppress it and clear the pending confirmation.

Send cooldown:
  Except for an explicit forced refresh, accept at most one activity heartbeat
  from the same device every 30 minutes.

Network failure:
  Retry only while the unlock gate remains accessible and HID input was seen
  within the last 15 minutes. Never replay stale activity as a new heartbeat.
```

The 6-12 hour range is the upper bound for refresh during continuous use, not
the polling interval. The second confirmed HID-class input epoch completes a
candidate; the first epoch never sends a heartbeat by itself.

The client must persist `last_successful_heartbeat_at`. If activity continues
but no heartbeat succeeds for more than 24 hours, it must show a tray error and
a local system notification. Local observation cannot replace a server
heartbeat or extend the server deadline.

### 6.4 Platform implementation

- Windows: session login/lock/unlock events plus current-session input age.
- macOS: a fixed nonsecret Data Protection Keychain sentinel with
  `WhenUnlockedThisDeviceOnly`, explicit non-synchronization, and no
  authentication UI; Quartz HID and Combined input ages; and documented
  workspace session and sleep/wake notifications.
- Linux: desktop-environment and Wayland support vary and do not block v1.

The macOS sentinel is an availability gate, not a secret or authentication
credential. Missing entitlement, missing or malformed sentinel data, Keychain
unavailability, and unexpected status codes all produce an unknown fail-closed
state. Production reads must also validate the sentinel's
`WhenUnlockedThisDeviceOnly` and non-synchronizable attributes; unexpected
metadata fails closed. The activity observer never reads the device signing
secret.

Prefer system APIs that report elapsed time since input. Do not install key
logging hooks or retain key codes, pointer coordinates, input content, native
event objects, application metadata, or window metadata. The frontend receives
no raw activity observations.

### 6.5 心跳认证

Device ID 只用于标识，不能作为认证凭据。

每台设备在首次绑定时生成独立签名密钥对：

- 私钥存入操作系统安全凭据存储；
- 服务端保存公钥；
- 心跳包含 `device_id`、单调递增 `sequence`、协议版本和签名；
- 服务端拒绝重复或倒退的 sequence；
- 服务端只使用收到请求的时间作为 `last_seen_at`；
- 所有请求使用 TLS。

服务端不需要接收活动类型、应用名称、URL 或输入内容。

### 6.6 多设备合并

```text
account.last_activity_at =
  MAX(所有 ACTIVE 设备被服务端接受的 last_seen_at)
```

任意一台未撤销设备出现有效活动，都延后账户期限。

设备必须支持：

- 用户可读名称；
- 最后活动时间；
- 主动撤销；
- 丢失标记；
- 长期休眠后重新验证；
- 新设备绑定确认；
- 每账户设备数量上限。

长期休眠设备重新上线时不能直接恢复心跳权限，默认超过 90 天未活动后需要邮箱或现有设备重新确认，防止已出售或被遗忘的旧电脑无限推迟通知。

## 7. 服务端状态机

### 7.1 状态定义

```text
ACTIVE
  │ 到达预警时间
  ▼
PRE_WARNING
  │ 到达不活跃期限
  ▼
GRACE_PERIOD
  │ 宽限期结束且仍无心跳
  ▼
RELEASED
  └─ 各 Recovery Grant 可被联系人分别领取
```

账户辅助终态包括 `DISABLED` 和 `DELETED`。`CLAIMED` 属于单个 Recovery Grant 的状态，`DELIVERY_FAILED` 属于单个通知任务的状态，不作为账户状态。

### 7.2 默认时间参数

| 参数         | 默认值 |  建议限制   |
| :----------- | :----: | :---------: |
| 不活跃期限   | 30 天  | 14～365 天  |
| 到期前预警   |  7 天  |  3～30 天   |
| 到期后宽限期 |  7 天  | 不少于 3 天 |

最终默认值需在用户测试后确定，但生产环境不得允许零宽限期。

### 7.3 状态转换规则

- `due_at = last_activity_at + inactivity_window`。
- `PRE_WARNING` 和 `GRACE_PERIOD` 中收到任何有效心跳，立即回到 `ACTIVE` 并重新计算期限。
- Owner 可在最终释放前通过已认证设备或账户页面暂停/重置流程。
- `RELEASED` 是安全边界；SRS 可能已被领取，系统不能声称能够撤回。
- 所有状态转换使用数据库事务和 compare-and-set 条件。
- 状态转换与通知任务通过 Transactional Outbox 同一事务写入。
- 邮件和短信发送使用稳定的幂等键，防止重复通知。

### 7.4 服务中断规则

服务恢复后不得根据过去的时间戳立即执行最终释放。

如果服务中断期间没有完成 Owner 预警：

1. 服务恢复后先进入或重新开始 `GRACE_PERIOD`；
2. 重新向 Owner 发送预警；
3. 从恢复时刻起等待完整的最小宽限期；
4. 宽限结束后才允许进入 `RELEASED`。

服务故障只能造成延迟，不能造成绕过预警的提前释放。

## 8. 密钥与紧急恢复设计

### 8.1 密钥层级

```text
随机 VDK ──────────────── 加密 Vault 数据
   │
   ├─ Master KEK ──────── 由 MP + Argon2id 派生
   │
   └─ Recovery KEK ────── 由 ERC + SRS + HKDF-SHA-256 派生
```

主密码和恢复路径都只包裹 VDK，不直接重新加密全部业务数据。

### 8.2 主密码路径

1. 随机生成至少 128-bit Salt。
2. 使用 Argon2id 从 MP 派生 256-bit Master KEK。
3. 使用 AES-256-GCM 包裹 VDK。
4. 本地保存 Salt、Argon2 版本、memory/time/parallelism 参数、nonce、密文和格式版本。
5. 修改主密码时只重新包裹 VDK。

Argon2 参数必须在目标硬件上基准测试并版本化，不允许只依赖库默认值。

### 8.3 延迟紧急恢复路径

- ERC 由客户端使用 CSPRNG 随机生成，至少提供 128-bit 熵，并带校验码。
- ERC 不允许由用户自定义为短密码或 PIN。
- 同一账户默认使用一个 ERC，降低用户保管负担；每台设备仍使用独立的 SRS 和 Recovery Wrapper。
- 每个设备或 Vault Recovery Record 对应独立的 256-bit SRS。
- Recovery KEK 使用标准 HKDF-SHA-256 派生：

```text
RKEK = HKDF-SHA-256(
  IKM  = ERC,
  salt = SRS,
  info = "Aeterna Recovery KEK v1" || vault_id || device_id
)
```

- 使用 AES-256-GCM 和独立随机 nonce 包裹 VDK。
- AAD 必须包含 `vault_id`、`device_id`、用途和加密格式版本。
- 客户端完成包装后清理内存中的 SRS、RKEK 和明文 VDK 副本。
- 服务端使用 KMS 加密保存 SRS，并严格限制解密权限。

在 `RELEASED` 之前，服务端拒绝返回 SRS。因此即使联系人提前拥有 ERC 和本地数据库，修改客户端也无法凭 ERC 单独解密。

### 8.4 领取与认证

- Recovery Contact 必须是已经验证的联系人。
- 最终通知包含短期、单用途 Claim Link，不包含 ERC 或主密码。
- 联系人再次通过邮箱 OTP 后取得 Claim Token。
- Claim Token 绑定 `account_id`、`contact_id`、`recovery_id`、有效期和允许操作。
- 客户端提交 Claim Token 和 Recovery ID 后领取 SRS。
- 领取行为写入不可变审计记录并通知所有 Owner 渠道和其他恢复联系人。

服务端链接可以“一次性领取”，但 SRS 一旦进入客户端便无法保证密码学意义上的一次性使用。因此用户界面使用“紧急恢复码”，不使用“一次性恢复密码”这一表述。

### 8.5 Owner 忘记主密码

Owner 忘记 MP 时不能通过普通邮箱验证码直接重置保险箱，否则邮箱被盗会变成 Vault 解密能力。

允许的自助恢复流程为：

1. 必须从仍然绑定、最近提交过有效心跳的设备发起；
2. 设备使用本地私钥签名 Owner Recovery 请求；
3. Owner 完成邮箱 OTP 等二次认证；
4. 服务端向全部 Owner 渠道发送安全通知并进入至少 24 小时冷静期；
5. 冷静期内未被取消，服务端只向发起设备释放其对应 SRS；
6. Owner 输入 ERC 解锁 VDK；
7. 应用强制设置新 MP，并轮换该设备的 SRS 和 Recovery Wrapper。

如果 MP 和 ERC 同时丢失，或者既无法使用已绑定设备又无法通过账户验证，Aeterna 无法恢复本地数据。人工客服只能处理付费权益或账户元数据，不能绕过密码学边界。

### 8.6 轮换与释放后的处理

- Owner 可以在释放前轮换 ERC；旧 SRS 必须被服务端撤销。
- 多设备轮换时，所有设备必须重新建立 Recovery Wrapper；UI 显示未完成设备。
- 已经 `RELEASED` 或任一 Recovery Grant 已经 `CLAIMED` 后，如果 Owner 重新出现，必须生成新 VDK 并重新加密本地数据，才能保护新的数据版本。
- 已经被联系人复制的旧密文、ERC 和 SRS 无法远程收回。

## 9. 多设备与本地备份

### 9.1 v1 范围

- 一个账户可以绑定多台设备。
- 各设备独立保存本地资料，内容可能不同。
- 新设备不会从服务端取得 ERC；Owner 必须在新设备设置时手动扫描或输入现有 ERC。
- 服务端只合并心跳，不判断数据是否一致。
- v1 不做实时同步、不做冲突合并、不上传保险箱密文。

### 9.2 备份与迁移

- 应用提供原子化的加密导出包和导入功能。
- 导出包包含 Vault Header、被包裹 VDK、密文数据、加密附件和认证后的 manifest。
- 不允许用户通过直接复制正在使用的 SQLite 文件作为官方备份方式。
- 导入新设备后必须重新注册设备并创建该设备的 SRS/Recovery Wrapper。
- UI 显示本地 Vault 版本和最近导出时间，但不向服务端上传文件内容。

如果所有本地设备和用户保存的备份同时损坏，Aeterna 无法恢复数据。这是 Local-First 模式的明确边界。

## 10. 本地保险箱设计

### 10.1 本地数据模型

```sql
CREATE TABLE vault_meta (
    vault_id TEXT PRIMARY KEY,
    schema_version INTEGER NOT NULL,
    crypto_version INTEGER NOT NULL,
    kdf_algorithm TEXT NOT NULL,
    kdf_params_json TEXT NOT NULL,
    kdf_salt BLOB NOT NULL,
    master_wrap_nonce BLOB NOT NULL,
    master_wrapped_vdk BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE recovery_wrappers (
    recovery_id TEXT PRIMARY KEY,
    vault_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    crypto_version INTEGER NOT NULL,
    recovery_wrap_nonce BLOB NOT NULL,
    recovery_wrapped_vdk BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (vault_id) REFERENCES vault_meta(vault_id)
);

CREATE TABLE vault_items (
    id TEXT PRIMARY KEY,
    vault_id TEXT NOT NULL,
    encrypted_payload BLOB NOT NULL,
    nonce BLOB NOT NULL,
    crypto_version INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY (vault_id) REFERENCES vault_meta(vault_id)
);

CREATE TABLE attachments (
    id TEXT PRIMARY KEY,
    vault_id TEXT NOT NULL,
    encrypted_path TEXT NOT NULL,
    encrypted_metadata BLOB NOT NULL,
    crypto_version INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (vault_id) REFERENCES vault_meta(vault_id)
);

CREATE TABLE local_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
```

资产标题、分类、联系人说明和正文都进入 `encrypted_payload`，不作为明文索引列。设备签名私钥和服务端 Refresh Token 不进入 SQLite，而是进入系统安全凭据存储。

### 10.2 加密约束

- 每次 AEAD 加密使用唯一 nonce。
- 不重复使用同一个 `(key, nonce)`。
- 所有格式包含明确的 `crypto_version`。
- 不自定义新的加密算法或未经审计的流式加密模式。
- 大附件必须使用经过审计的流式 AEAD 实现；在实现选型完成前，原型限制附件大小并使用整文件 AEAD。
- Rust 内存中的密码和密钥使用 `secrecy`/`zeroize` 等机制尽快清理。
- 禁止在日志、panic、遥测、剪贴板历史或错误信息中输出秘密。

SQLite 的 WAL、journal 和临时文件必须只接触密文。应用启用安全删除策略，但不承诺在 SSD、快照或备份系统上完成物理不可恢复删除；建议用户同时启用 FileVault 或 BitLocker。

The cryptographic wrapper version, SQLite schema version, local container
version, and export-package version are independent. I02 fixtures do not define
a production persistence format. I05 must approve the local schema/container
and migration plan before persistent writes; I07 separately owns the export
package and import staging protocol. Unknown versions and hostile lengths fail
before allocation or KDF work.

### 10.3 Tauri 权限边界

- React/WebView 不直接访问 SQLite、密钥、文件系统或系统输入事件。
- 所有 Vault 操作由 Rust Core 提供窄接口。
- 不向 WebView 开放任意 SQL execute/select 能力。
- Tauri capabilities 按窗口、命令和路径最小授权。
- 恢复窗口、设置窗口和普通内容窗口使用不同 capability。
- 启用严格 CSP，不在高权限主窗口加载远程脚本。

## 11. 云端服务设计

### 11.1 服务职责

- 邮箱验证和账户恢复；
- 设备注册、撤销和公钥管理；
- 接收签名心跳；
- 维护账户状态机；
- 保存通知策略、联系人和通知文本；
- 加密保存 SRS 并执行延迟释放；
- 邮件和短信发送；
- 支付回调、授权和短信额度；
- 审计、限频和滥用防护。

### 11.2 云端数据模型

```sql
CREATE TABLE accounts (
    id UUID PRIMARY KEY,
    email_ciphertext BYTEA NOT NULL,
    email_lookup_hmac BYTEA UNIQUE NOT NULL,
    locale TEXT NOT NULL,
    state TEXT NOT NULL,
    inactivity_days INTEGER NOT NULL,
    warning_days INTEGER NOT NULL,
    grace_days INTEGER NOT NULL,
    last_activity_at TIMESTAMPTZ,
    due_at TIMESTAMPTZ,
    grace_started_at TIMESTAMPTZ,
    released_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE devices (
    id UUID PRIMARY KEY,
    account_id UUID NOT NULL REFERENCES accounts(id),
    label_ciphertext BYTEA NOT NULL,
    public_key BYTEA NOT NULL,
    last_sequence BIGINT NOT NULL DEFAULT 0,
    last_seen_at TIMESTAMPTZ,
    status TEXT NOT NULL,
    bound_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ
);

CREATE TABLE recovery_grants (
    id UUID PRIMARY KEY,
    account_id UUID NOT NULL REFERENCES accounts(id),
    device_id UUID NOT NULL REFERENCES devices(id),
    encrypted_srs BYTEA NOT NULL,
    kms_key_version TEXT NOT NULL,
    status TEXT NOT NULL,
    released_at TIMESTAMPTZ,
    claimed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE contacts (
    id UUID PRIMARY KEY,
    account_id UUID NOT NULL REFERENCES accounts(id),
    email_ciphertext BYTEA NOT NULL,
    email_lookup_hmac BYTEA NOT NULL,
    phone_ciphertext BYTEA,
    role TEXT NOT NULL,
    consent_status TEXT NOT NULL,
    verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE notification_templates (
    account_id UUID PRIMARY KEY REFERENCES accounts(id),
    owner_message_ciphertext BYTEA NOT NULL,
    contact_message_ciphertext BYTEA NOT NULL,
    version INTEGER NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE outbox_events (
    id UUID PRIMARY KEY,
    account_id UUID REFERENCES accounts(id),
    event_type TEXT NOT NULL,
    idempotency_key TEXT UNIQUE NOT NULL,
    payload_ciphertext BYTEA NOT NULL,
    scheduled_at TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE delivery_attempts (
    id UUID PRIMARY KEY,
    outbox_event_id UUID NOT NULL REFERENCES outbox_events(id),
    provider TEXT NOT NULL,
    provider_message_id TEXT,
    channel TEXT NOT NULL,
    status TEXT NOT NULL,
    error_code TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

支付、授权和短信额度使用独立表。不得信任客户端本地的 `is_pro` 或 `sms_quota`。

### 11.3 心跳存储最小化

- 账户表只保存聚合后的最后活动时间。
- 设备表只保存每台设备最新心跳和 sequence。
- 调试/安全审计日志设置短期 TTL，不永久保存行为历史。
- 不保存键盘、鼠标、应用、URL 或活动原因。

### 11.4 关键 API

```text
POST   /v1/auth/email/start
POST   /v1/auth/email/verify
POST   /v1/devices/register
POST   /v1/devices/{id}/confirm
DELETE /v1/devices/{id}
POST   /v1/heartbeat
PUT    /v1/policy
POST   /v1/contacts
POST   /v1/contacts/{id}/verify
POST   /v1/notifications/test
POST   /v1/recovery/claim/start
POST   /v1/recovery/claim/verify
POST   /v1/recovery/{id}/release-secret
POST   /v1/recovery/owner/start
POST   /v1/recovery/owner/confirm
POST   /v1/billing/webhook
DELETE /v1/account
```

所有写接口使用幂等键、限频和结构化审计。支付 Webhook 必须验签并具有独立幂等处理。

The public client repository owns versioned machine-readable protocol schemas,
stable error codes, signature canonicalization rules, bounds, and synthetic
fixtures. Both the client and private control plane consume the same pinned
protocol release or exact fixture digest. Neither private persistence models nor
client implementation types are the contract source of truth. I09 selects the
exact schema and canonical byte encoding before either repository implements
public endpoints.

### 11.5 账户与邮箱恢复

- 从有效绑定设备修改邮箱时，需要设备签名、新邮箱验证和冷静期；旧邮箱收到变更通知。
- 没有可用设备时，原邮箱验证只能恢复云端账户管理权限，不能恢复本地 Vault。
- 原邮箱和所有设备同时丢失时，可通过支付凭证进行人工权益迁移，但人工流程不能获取 SRS、ERC、VDK 或解密本地数据。
- 新设备仅凭邮箱 OTP 不能立即获得心跳资格；需要现有设备确认或经过延迟风控流程。

## 12. 通知系统

### 12.1 通知层级

| 层级           | 渠道             | 用途                       |
| :------------- | :--------------- | :------------------------- |
| Owner Warning  | 邮件 + 本地通知  | 到期前和宽限期内阻止误触发 |
| Base Contact   | 云端邮件         | 最终释放后的基础通知       |
| Pro Contact    | 邮件 + 短信      | 最终释放后的多渠道通知     |
| Recovery Claim | 带时限链接 + OTP | 领取 SRS，不包含 ERC       |

`mailto:` 仅可作为设置和测试时的辅助渠道，不承担最终自动通知职责。

### 12.2 通知内容约束

- 使用固定安全模板为主。
- 自定义内容使用纯文本、长度上限和严格转义。
- 禁止附件、任意 HTML、邮件头和可执行内容。
- UI 强提醒不得填写主密码、ERC、助记词、资产密码或其他秘密。
- 可以填写设备位置、密封信封位置和恢复步骤。
- 联系人地址和正文在服务端字段级加密，但发送供应商仍能看到发送内容。

### 12.3 联系人验证与防滥用

- Recovery Contact 必须完成邮箱验证或明确同意。
- 提供测试通知，验证地址可达性。
- 联系人可拒绝或退订非必要通知。
- 对账户、设备、IP、邮箱和手机号实施分层限频。
- Turnstile 等浏览器挑战只在独立低权限验证页面运行，不加载到 Vault 主窗口。
- 自定义文本和 URL 受到限制，防止把系统用作匿名骚扰或钓鱼渠道。

### 12.4 计费原则

核心恢复不能在触发时才发现订阅或额度不足：

- 基础邮件通知和已经配置的 Recovery Release 不因 Pro 过期而静默失效。
- 短信可以是付费增强，但必须在预警阶段提前检查额度。
- 短信额度不足时通知 Owner，并保留邮件兜底。
- 关键通知任务不得依赖客户端本地授权状态。
- 商业模型必须覆盖长期服务成本，不使用“永久免费、永久可用”承诺。

## 13. 隐私与数据生命周期

### 13.1 服务端处理的个人数据

- Owner 邮箱；
- 联系人邮箱和可选手机号；
- 设备名称、公钥和最后活动时间；
- 不活跃策略；
- 通知文本和位置说明；
- 支付、授权和发送记录；
- Recovery Claim 审计记录。

产品隐私说明必须如实披露这些数据，而不是继续使用“零后端”或“零个人数据”表述。

### 13.2 数据最小化

- 邮箱查询使用带服务器秘密的 HMAC 索引，不存普通哈希作为唯一保护。
- PII 和通知正文使用字段级加密。
- 日志不记录正文、Token、SRS、ERC 或完整联系方式。
- Delivery Log 只保留必要的 provider ID、状态和错误码。
- 行为审计设置明确 TTL。
- 用户可以导出账户配置并删除账户。

### 13.3 删除语义

删除账户将：

- 撤销所有设备；
- 删除联系人和通知模板；
- 销毁或排队销毁所有 SRS；
- 取消未来通知任务；
- 使延迟紧急恢复永久不可用。

执行前必须二次确认，并要求用户先生成新的离线恢复方案。

## 14. 威胁模型

### 14.1 主要防护目标

- 设备磁盘被离线复制时，保险箱内容保持不可读。
- 服务端数据库泄露时，攻击者不能单独解密本地保险箱。
- 联系人提前获得 ERC 时，不能在最终释放前解密。
- 网络攻击者不能伪造或重放有效心跳。
- 被撤销、复制或长期遗忘的设备不能无限延后流程。
- 服务中断不能绕过预警和宽限期造成提前释放。

### 14.2 明确不防护

- 已解锁且被恶意软件完全控制的操作系统；
- 键盘记录器、屏幕录制和内存提取；
- 恶意或被盗的有效设备持续提交签名心跳；
- 掌握唯一设备、电脑密码和 ERC 的恶意联系人主动阻断心跳并等待最终释放；Owner 预警、多设备和宽限期只能降低此风险；
- 知道操作系统密码的人访问 Aeterna 之外的数据；
- Owner、联系人与服务端运营方串通；
- 已经正式释放并被复制的数据；
- 无任何本地副本时的硬件损坏；
- 邮件供应商、短信供应商或互联网长期不可用。

### 14.3 安全工程要求

- 发布前完成独立密码学设计审查和桌面端渗透测试。
- 依赖锁定、漏洞扫描、许可证审查和供应链审计。
- 安装包、自动更新和配置清单必须签名。
- CI 执行单元测试、属性测试、迁移测试和恢复演练。
- 模糊测试加密容器、导入文件和 IPC 输入。
- 生产密钥使用 KMS/HSM；开发、测试、生产完全隔离。
- 权限最小化，管理员不能通过常规后台页面直接读取 SRS。

## 15. 可用性与故障处理

| 故障           | 处理原则                                               |
| :------------- | :----------------------------------------------------- |
| 单台设备损坏   | 其他设备仍可提交心跳；本地资料是否存在取决于用户备份   |
| 所有设备离线   | 进入正常预警和宽限流程                                 |
| 客户端网络中断 | 只重试新鲜活动，不重放陈旧活动                         |
| 服务端中断     | 延迟状态机；恢复后重新执行完整宽限期                   |
| 邮件失败       | 重试、备用渠道、Owner 警告和人工可见状态               |
| 短信不足       | 提前警告，邮件兜底                                     |
| 联系人地址失效 | 测试通知、退信检测、在 Owner 活跃时提示更新            |
| SRS 数据丢失   | 加密备份、跨区域复制和定期恢复演练；丢失时无法紧急恢复 |
| 项目停止运营   | 提前通知并提供将延迟恢复转换为离线恢复的迁移工具       |

项目终止计划是核心能力。若云端服务计划关闭，应允许 Owner 在已认证状态下获取并本地封装必要恢复材料，使 ERC 转换为不依赖 Aeterna 服务端的离线恢复路径。

## 16. 国际化

- v1 从第一天使用 `react-i18next`。
- 默认语言为英文，同时支持简体中文；日文和西班牙文列入后续版本。
- 所有 UI、邮件、短信、错误信息和恢复说明使用 i18n key。
- 日期和数字使用 `Intl.DateTimeFormat` / `Intl.NumberFormat`。
- 服务端统一使用 UTC，客户端仅在展示时转换时区。
- CSS 使用逻辑属性，为 RTL 预留。
- ERC 使用语言无关编码或经过版本化的词表，并带校验码。
- 用户自定义通知保持原文，不做自动机器翻译。

## 17. 技术栈

### 17.1 桌面端

- React + TypeScript
- Tailwind CSS + Shadcn UI
- Tauri v2
- Rust Core
- SQLite，由 Rust `sqlx` 等受控数据层访问
- 系统原生会话/输入时间 API
- macOS Keychain / Windows Credential Manager 或平台安全存储

### 17.2 密码学

- Argon2id：主密码 KDF
- AES-256-GCM：小型记录和 VDK 包裹
- HKDF-SHA-256：Recovery KEK 派生
- Ed25519 或平台支持的等价签名算法：设备请求签名
- CSPRNG：VDK、ERC、SRS、nonce 和 Token
- `secrecy` / `zeroize`：内存秘密生命周期

The G0 implementation decision accepts exact pinned primitive crates,
bounded versioned wrapper semantics, and a provisional hardware-specific KDF
profile so I05 can proceed. It does not freeze a production container, release
KDF default, signing identity, or UX and does not claim an independent audit.
G1 owns independent cryptographic, dependency, native-storage, side-channel,
fuzzing, and penetration review before release. 禁止使用已弃用的
`sodiumoxide`，禁止自行实现密码学原语或新的文件加密格式。

### 17.3 服务端

- Python 3.14 + FastAPI（异步 API 与管理接口）
- SQLAlchemy 2 + Alembic + PostgreSQL（事务性状态和 Outbox）
- Redis + Celery Worker / Beat（队列、重试和定时状态机）
- KMS/HSM（生产环境的 SRS 与 PII 字段密钥）
- 邮件供应商适配层
- 短信供应商适配层
- 托管的邮箱验证与支付页面

官方服务端代码作为独立私有仓库维护。客户端公开仓库必须包含协议、数据边界、可观测网络行为和自托管兼容性所需的公开说明，但不得因此声称官方托管服务本身开源。服务端禁止提供 Vault、留言、影像或附件的上传接口。

## 18. 测试与验收标准

### 18.1 活动检测

- 仅开机或自启动不会产生心跳。
- 锁屏状态下的后台活动不会产生心跳。
- 解锁后出现输入，规定时间内产生一次心跳。
- 长时间空闲后的第一次输入立即产生心跳。
- 持续活动不会造成高频请求。
- URL、按键内容、窗口标题不进入日志或请求。

### 18.2 心跳安全

- 重放的 sequence 被拒绝。
- 撤销设备的签名心跳被拒绝。
- 修改 payload 后签名验证失败。
- 客户端时钟前后调整不改变服务端截止时间。
- 多设备并发心跳使用服务端最大接收时间。

### 18.3 状态机

- PRE_WARNING/GRACE 中的有效心跳原子取消流程。
- 心跳和 RELEASE 并发时只有一个确定结果。
- 定时任务重复执行不会重复发送通知。
- 服务中断恢复后不会立即越过宽限期释放。
- RELEASED 后所有领取均产生审计和通知。

### 18.4 密码学恢复

- MP 可以独立解锁。
- ERC 在没有 SRS 时无法解开 VDK。
- SRS 在没有 ERC 和本地 Vault 时无法解密任何用户数据。
- RELEASE 前领取接口始终拒绝。
- RELEASE 后正确 ERC + SRS 可以恢复。
- 错误 ERC、错误设备 SRS、错误 AAD 或篡改密文全部失败。
- 主密码修改不需要重新加密 Vault 内容。
- ERC 轮换使旧 SRS/Wrapper 失效。
- Owner 自助恢复必须满足绑定设备签名、二次认证和冷静期。

### 18.5 备份与恢复

- 导出过程中断不会产生被标记为成功的损坏备份。
- 导入包篡改可被检测。
- 新设备导入后创建新的设备凭据和 Recovery Wrapper。
- 从至少两个独立副本完成定期恢复演练。

## 19. 实施阶段

### Phase 0 — 风险原型

- Complete the macOS unlock, recent-input, secure-storage, lifecycle, and remote-session risk prototypes.
- Keep the Windows adapters as an implementation checkpoint until the separate real-Windows qualification gate.
- OS 安全存储和设备签名 Spike。
- MP/ERC/SRS 双路径包装原型。
- 服务端状态机和竞态模型测试。
- G0 accepts only the implementation-scoped primitive, wrapper, storage-boundary,
  state-machine, and protocol-direction decisions needed for Phase 1.
- G1 independently reviews and freezes release cryptography after I05-I14;
  production signing, container, migration, recovery UX, and audit evidence are
  not falsely claimed complete in Phase 0.

### Phase 1 — 本地 Vault MVP

- Vault Engine、主密码和本地附件。
- 加密导入/导出。
- ERC 生成、打印和保管引导。
- Productionize the macOS activity agent; Windows production lifecycle work remains gated separately.
- i18n、严格 Tauri capability 和 CSP。

### Phase 2 — Heartbeat 与通知服务

- 账户、设备、联系人和策略。
- 签名心跳和多设备聚合。
- PRE_WARNING/GRACE 状态机。
- 邮件通知、Outbox、重试和审计。

### Phase 3 — 延迟紧急恢复

- SRS KMS 存储与 Release Policy。
- Claim Link、OTP 和领取审计。
- 多设备 Recovery Wrapper。
- ERC 轮换和释放后重新加密流程。

### Phase 4 — 商业化与强化

- 短信增强、支付和签名 entitlement。
- 灾备、区域冗余、项目终止迁移工具。
- 渗透测试、外部密码学审查和正式发布。

## 20. 发布前仍需确定的参数

以下事项不会改变核心架构，但必须在生产发布前通过原型、用户测试或商业决策确定：

1. The initial production release supports macOS only. G0 accepts an Apple
   Silicon macOS 15.0 product/test floor, subject to the I08
   minimum-floor/current-release native matrix before a support claim. GW
   decides the later Windows floor independently.
2. 不活跃期限、预警期和宽限期的默认值与最小值。
3. 每账户最大设备数和联系人数量。
4. 大附件的受审计流式加密格式与 v1 文件大小上限。
5. 邮件、短信、KMS、支付和数据库的最终供应商及数据驻留区域。
6. 联系人同意、拒绝和地址失效后的具体产品流程。
7. 免费邮件、短信额度与长期服务成本模型。
8. 审计日志和发送记录的具体保留期限。

这些是实施和运营参数，不再构成当前架构的未解核心矛盾。进入 Phase 0 后，任何活动检测或密码学原型未达到验收标准，都必须先更新本文档和对应 ADR，不能通过降低安全要求绕过。
