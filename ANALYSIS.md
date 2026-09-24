# OTA 内测包下载失败（业务码 2713）调查全记录

调查时间：2026-09-24 ~ 09-25
设备：一加 13 / PJZ110 / Android 16 (SDK 36)
ROM：`PJZ110_16.0.10.501(SP01CN01)`
fingerprint：`OnePlus/PJZ110/OP5D0DL1:16/BP2A.250605.015/V.58c08ac-32ff28e-33c0954:user/release-keys`
目标包：`my_manifest_PJZ110_11.F.04_2040_202609192316.97.081ee7fc_patch`
环境：KernelSU + LSPosed，bootloader 已解锁

---

## 0. 一句话结论

**客户端代码没有问题，2713 是服务端业务码。**
客户端按源码规则完整、正确地构造并发送了 gkaReq=2 认证请求；
服务端以 HTTP 200 回复一个 49 字节的 JSON：`{"body":null,"errMsg":"2713","responseCode":2713}`。
APK 内对 2713 没有任何定义、映射或文案。

失败的那一环在**设备完整性**：`packIdAttestation()` 恒为 false、
`CryptoengManager: Cryptoeng Service return fail`，
导致 attestation 缺少 ID 段（含 `isOemLock` / `rootState` / 设备身份字段）。

---

## 1. 结论的证据强度分级

混着说是会误导人的，所以分开写。

| 强度 | 结论 | 依据 |
|---|---|---|
| **强**（实测多次复现） | 客户端 gkaReq=2 认证链完整正确 | id/ts/ac/as 四头齐全、ac 3200~3204、as 96、ECDSA `sign result byte[70]`、`/ts` HTTP 200、`/download` HTTP 200 |
| **强** | 2713 是服务端透传，APK 内零定义 | 全树搜独立 token `2713` = 0 处；来源为 `u7/a.java:96` 的 `optInt("responseCode", 2)` |
| **强** | ID attestation 未生成 | `packIdAttestation() = false`（r13 起每轮必现）+ CryptoEng HAL 返回 fail |
| **强** | 服务端明确判"非内测设备" | 查询响应解析后写入 `is_recruit=false`、`recruitType=""`；`n5.h.D1()` 实测 false |
| **中**（推论） | 服务端因 attestation 缺 ID 段而拒 | 机制自洽，但服务端逻辑不可见 |
| **弱**（未证明） | 根因是 BL 解锁导致 TEE 拒绝 | 排除法后唯一剩下的候选，**没有直接证据** |

---

## 2. 时间线：每一轮证明到哪一步

| 轮次 | 新增能力 | 证明到 |
|---|---|---|
| r11 | KeyRepair 让位 | SDK/系统自己造密钥（`android.provider.BeandCupClalt.createApplicationPublicKey`）；我们的修复全程空转，r14 起关闭 |
| r12 | 全量回显 OTA 日志 | `cryptoeng_hidl: no permission calling cmd:10009/10013` |
| r13 | CryptoEng 命令枚举 + 客户端扫描 | command=10015、`pkiCommonAsk() -> byte[2512]`、`packIdAttestation() -> false` |
| r14 | `ResultParser`/`Util` 判定观察 | `isParseSuccess=true`、`isMethodExecuteSuccessV2=true`、`generateX509` 是 **void**（不能把 `return null` 当失败） |
| r15 | gkaReq=2 下载请求端到端观察 | `b.a(..,2)` 被调用；id/ts/ac/as 四头抓到；`/ts` 200 |
| r16 | `/download` 的 status 与 streamVia | `realHttpStatus=200`、`streamVia=getInputStream` |
| r17 | 三个静默失败入口 | 无 `b.a threw`、GUID 非空（len=64）、`tsUsed == tsBody`（ts 来自服务端，未回退本地时钟） |
| **r18** | **修过滤器 bug** | `/download` 的 status/stream/body 首次全部打出 |
| r19 | 内测资格状态观察 | `D1 recruited=false`；`is_recruit=false` / `recruitType=""` 是**服务端写入**的 |
| r20 | attestation 完整性字段尝试 | 落空（`ParsedAttestationRecord` 客户端从不调用）；但复现了 `packIdAttestation=false` |
| r20_no_spoof | 停用隐藏模块对照 | 与 r20 **逐项完全一致** → 隐藏模块无关 |

---

## 3. 客户端链路（源码级）

### 3.1 下载请求的发起与判定 —— `u7/a.java`（GetInfoThread）

```java
:365   str = dVar.f2836c;                    // auto_download=false → mManualUrl (= PackageListInfo.f6261h)
:60    new URL(str).openConnection()
:64-65 GET + Range: bytes=0-
:66    addRequestProperty("userId", "oplus-ota|" + <OTA App versionCode>)   // 不是账号
:67    addRequestProperty("marketName", Base64(ro.vendor.oplus.market.name))
:68    i9 = b.i(context)                     // gka_req_download = 2
:69-73 if (i9∈{1,2}) && dVar.w ∈ {0,1} → b.a(conn, ctx, str, i9)
:78    responseCode = getResponseCode()
:79    206 → b(conn)                          // ← 成功路径：分段下载
:81    301/302 → 跟随 Location
:84    !=200 → DownloadException(2, code, "unsupported")
:88-96 200 → 读完 body → 打 "download denied, response msg:"
           → throw new DownloadException(2,
                 new JSONObject(body).optInt("responseCode", 2), body)
```

> **`206` 才是成功，`200` 在客户端语义里就是"被拒绝"。**
> 服务端这次回 200 + JSON，连包体都没开始发。
> 同样的逻辑在 `b7/b.java:127`（DownloadFilePieceThread）有一份副本。

### 3.2 四个认证头 —— `com/oplus/ota/downloader/util/b.java`

```java
:58  strM       = m(k(context))     id  = MD5(getOpenid(context, GUID))     // k() :224
:59  strValueOf = String.valueOf(p(context))
                                    ts  = GET ${component_update_url}/ts 的 body 解析成 long   // p() :278-311
:60-65 uri = new URI(str).getPath()+query → replaceFirst("/","") → replace("=",":")
:68  strJ = bVarL.o()               ac  = OPLUS PKI attestation 证书链 Base64
:69  strC = d(bVar)                 as  = Base64(SHA256withECDSA(p5.b.t()))
:78-81 addRequestProperty: id / ts / ac / as
```

`p5/b.java:499` `t()` = `JSONObject{id, ts, uri}.toString()`（字段顺序 id→ts→uri）。

**两个静默回退**（不报错，日志里能一票否决）：
- `p()`：`/ts` 非 200 或 body 空 → `ts` 回退 `System.currentTimeMillis()`。**r17 实测未触发**（`tsUsed == tsBody`）
- `k()`：`getOpenid` 抛异常 → 返回 `""` → `id` 变 `MD5("") = d41d8cd98f00b204e9800998ecf8427e`。**r17 实测未触发**（guid len=64）

### 3.3 2713 的来源

APK 全树（sources + resources）搜独立 token `2713`：**0 处**；`0xA99`：**0 处**。
唯一 27xx 常量是 `i3/g.java:11` 的 `{0,1350,2700,4050}`（动画时长，无关）。
allawn `ExceptionCode` 只有 `10000` / `30016` / `-1`。

它唯一的来源是 `u7/a.java:96` 的 `optInt("responseCode", 2)`——**服务端 body 字段的原样拷贝**。
`mCode` 恒为 `2` = `EXCEPTION_SERVER_SUPPORT_CODE`；`mGKACode = 2713` 只被存进
`PackageListInfo.K`（`b7/e.java:59`）做持久化，没有任何 switch 或提示文案。

### 3.4 内测资格（recruit）链路

```java
n5/h.java:310-312   D1(ctx) = !isEmpty(Settings.Global "recordOtaRecruitAid")   ← 那扇门
h0.java:944,1198    recruitType / is_recruit 来自服务端查询响应 JSON
StrategyReceiver.java:240-260  只有广播 ACTION_OTA_RECRUIT_SUCCESS 才写 recordOtaRecruitAid
v7/a.java:406/438/1891         升级成功后把 recordOtaRecruitAid 清成 null
a/a.java:470-480   OtaAccountUtil.T()：账号 userId 变化 → 清 recruit_account_info_agreed
AppointmentActivity.java:469   只有报名页会置 recruit_account_info_agreed = true
```

r19 实测：`D1 recruited=false`，`is_recruit=false` ×2，`recruitType=""` ×2，
`recordOtaRecruitAid` 恒 null，`putString recordOtaRecruitAid` **出现 0 次**。

### 3.5 attestation 里的设备完整性字段

`com/allawn/cryptography/security/attestation/ParsedAttestationRecord.java`
（`EXTENSION_OID = 1.3.6.1.4.1.11129.2.1.25`，标准 Android Key Attestation）：

```
rootState             VerifiedBootState: VERIFIED / UNVERIFIED / SELF_SIGNED / FAILED
oemLockState          optInt("isOemLock", -1)   :155 ；CBOR map.get("isOemLock")  :225
deviceSecurityLevel   SOFTWARE / TRUSTED_ENVIRONMENT / STRONG_BOX
attestationIdBrand / Device / Imei / Manufacturer / Model / Product / Serial
```

这些随 `ac` 发给服务端。**但 r20 实测：该类在客户端这条链里从未被实例化**（hook 装上，
运行时命中 0 次）—— 客户端不检查，只有服务端解析。

---

## 4. 被推翻的判断（诚实记录）

这几条都曾经被我当作结论说过，后来被证据否掉。**留着，避免重走。**

| # | 曾判断 | 被什么否掉 |
|---|---|---|
| 1 | 2713 = 新密钥未注册 | attestation 链实测全绿；APK 内零定义，2713 是服务端字段 |
| 2 | "没登录 OPPO 账号"导致 | 账号在 **`persistent_info.xml`**（我只在 `state_info.xml` 里找）：`recruit_account_user_id=496521302`、`recruit_account_user_name=a23bc123` |
| 3 | 前置包 base 不匹配导致 patch 被拒 | 反证：`manualUrl` 是服务端**这次查询后专门下发**给这台设备的，base 不对它根本不会推 |
| 4 | 能从 `ParsedAttestationRecord` 读到 oemLock/rootState | 该类客户端从不调用，运行时 0 命中 |
| 5 | 隐藏模块破坏了 CryptoEng | r20 与 r20_no_spoof **逐项完全一致**（cryptoeng fail 4/4、packIdAttestation false 1/1、ac 3200、2713 4/4） |
| 6 | vendor 镜像混刷 | 三处 fingerprint 逐字节一致；vendor 构建时间晚 2h21m 是官方流水线正常现象 |

---

## 5. 已排除清单

- 客户端代码（id/ts/ac/as、签名、`/ts`、HTTP 处理）—— 逐项验证通过
- APK 内有 2713 的定义 —— 零命中
- ts 静默回退本地时钟 —— 未触发
- GUID 取不到 —— 未触发（len=64）
- `b.a()` 抛异常导致无认证头 —— 0 次
- 招募模块/隐藏模块干扰 —— 对照实验一致
- vendor/system 镜像不匹配 —— fingerprint 一致
- vendor TA 损坏 —— 同上

---

## 6. 可复现命令

```bash
# 认证链状态
adb logcat -s OplusOtaTracer | grep -E "\[DlReq\]|\[Recruit\]|\[Attest\]"

# 设备完整性状态（注意：会被隐藏模块改写）
adb shell getprop ro.boot.verifiedbootstate     # orange = 已解锁
adb shell getprop ro.boot.flash.locked          # 0 = 已解锁
adb shell getprop ro.boot.vbmeta.device_state   # unlocked

# 镜像一致性
adb shell getprop ro.build.fingerprint
adb shell getprop ro.vendor.build.fingerprint
adb shell getprop ro.odm.build.fingerprint

# 内测资格
adb shell settings get global recordOtaRecruitAid
adb shell su -c 'grep -iE "is_recruit|recruitType" /data/data/com.oplus.ota/shared_prefs/state_info.xml'
adb shell su -c 'grep -iE "recruit_account" /data/data/com.oplus.ota/shared_prefs/persistent_info.xml'
```

> Windows PowerShell 里没有 `grep`，用：
> `adb logcat | Select-String -Pattern "OplusOtaTracer"`

---

## 7. 给 OPPO 的反馈模板

```
设备：一加 13 / PJZ110_16.0.10.501(SP01CN01)
包：my_manifest_PJZ110_11.F.04_2040_202609192316.97.081ee7fc_patch

现象：点击下载内测包立即失败，服务器返回业务码 2713。

实测（客户端侧已逐项验证正确）：
  id / ts / ac / as 四个认证头齐全（ac 3200 字节证书链、as 96 字节签名）
  ECDSA 签名成功（sign result byte[70]）
  /ts 返回 HTTP 200，ts 取自服务端，未回退本地时钟
  /download 返回 HTTP 200 + {"body":null,"errMsg":"2713","responseCode":2713}

但：
  packIdAttestation() 恒为 false
  CryptoengManager: commonGetResult: Cryptoeng Service return fail
  服务端查询响应写入 is_recruit=false、recruitType=""
  Settings.Global recordOtaRecruitAid 恒为 null，从未收到
    oplus.intent.action.ACTION_OTA_RECRUIT_SUCCESS

请求：
  1. 说明 2713 的业务含义（客户端 APK 内无任何定义，用户无法自助判断）
  2. 修复"更新前置包后内测资格消失"的问题（社区多人复现），
     疑似 v7/a.java 在升级成功分支清空 recordOtaRecruitAid 后未恢复
  3. 附带问题：刷入官方前置包后设备无法进入 fastboot，叠加 ARB=1 熔断，
     用户完全失去回退能力
```

---

## 8. 产物索引

```
logs/
  r11.log            早期（2304 阶段）
  r15.log ~ r20.log  gkaReq=2 端到端观察
  r20_no_spoof.log   停用隐藏模块的对照

artifacts/
  r13/ r14/ r15/ r16/ r17/ r18/ r19/ r20/
    debug/app-debug.apk

decompiled/src/sources/     jadx 反编译产物（未纳入 git，见 .gitignore）
```

关键源码位置速查：

| 位置 | 内容 |
|---|---|
| `u7/a.java:60,78,96` | 下载请求发起 / status 判定 / 2713 抛出点 |
| `com/oplus/ota/downloader/util/b.java:54-84` | 四个认证头生成 |
| `p5/b.java:499` | 被签名的 JSON |
| `DownloadException.java:13` | `EXCEPTION_SERVER_SUPPORT_CODE = 2` |
| `n5/h.java:311` | `D1()` 内测设备判定门 |
| `h0.java:944,1198` | `recruitType` / `is_recruit` 来源 |
| `StrategyReceiver.java:240-260` | 招募成功广播写入 recruitId |
| `v7/a.java:406,438,1891` | 升级成功后清空 recruitId |
| `ParsedAttestationRecord.java:49,155,388` | `oemLockState` / `rootState` |
| `z6/b.java:44` | `DownloadRequest.mDownloadType`（gka 头的前置闸门） |

---

## 9. 未解决的问题

1. **2713 的业务含义** —— 服务端不可见，不可推断。
2. **CryptoEng 拒绝的具体原因** —— 是 BL 解锁、SELinux 策略，还是服务授权问题？
   客户端无法区分。这是唯一还没闭合的环。
3. **`is_recruit=false` 与 CryptoEng 失败的因果关系** —— 是先有资格判定失败，
   还是先有设备完整性失败导致资格不被认可？分不开。

---

## 10. 方法论备注

这一轮里起作用的是**排除法 + 可证伪的对照实验**，不是读代码猜：

- 每一条结论都落到能重跑的命令或能数出来的日志上
- 判断被否掉时立刻写明"作废"并把原因留下（见第 4 节）
- 代价大的操作（上锁 BL 会清机）**必须先有判据**，不能凭推测让用户承担

r20_no_spoof 那次对照是最划算的一次：5 分钟、零代价，一次性排除了"隐藏模块"这个变量。
