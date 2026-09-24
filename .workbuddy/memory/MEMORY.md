# oplus.ota 项目长期约定

## 项目性质

`com.oplus.ota`（OPPO/一加 OTA）下载流程的诊断 + 修复 LSPosed 模块。
目标问题：点击「下载内部测试包」出现 `ecdsaSignPki exception: No installed provider
supports this key: (null)` 及后续 `DownloadException` / `responseCode=2304`。

**诊断已闭环**（见下方结论），当前目标是**真的能下载成功**，因此新增修复模式
（`TracerConfig.ENABLE_KEY_REPAIR`，默认开）。

## 硬约束

- **只观察，不干预**：任何 hook 都不得调用 `setResult()`、修改 `param.args`、
  设置/清除 throwable。CI 有 grep 门禁强制这条。不绕过签名、完整性、权限、服务端校验。
- **不打印敏感内容**：私钥、签名原文、token、密码一律不打印。Key 只打
  class/algorithm/format/encodedLen；byte[] 只打长度；String 打长度+sha256 摘要；
  URL 只打 host+path 与 query 参数名；未知对象只打 class name，绝不 `toString()`。
- **日志 TAG 统一** `OplusOtaTracer`，`logcat -s OplusOtaTracer` 即可过滤。
- **不做全包方法 hook**：只 hook 具名入口；GetInfoThread 每类上限 12 个方法；
  共享类（KeyStore / HttpURLConnection / Log）带调用栈过滤。
- **安全失败**：找不到类/方法只记录一次，绝不让 OTA App 崩溃。
- **绝不 hook 类加载路径**（`ClassLoader#loadClass` 等），更不能在回调里做反射
  （`getDeclaredMethods()` / `Class.forName`）。首版这么干过：启动期嵌套类加载 →
  应用 ClassLoader 损坏 → `:ui` 进程黑屏。所有反射只在后台线程做，且限流。

## 诊断结论（真机验证，可稳定复现）

根因：AndroidKeyStore 里没有 alias `ota_pki_attest` 的 EC 私钥；App 调
`containsAlias` 拿到 `false` 后无任何分支，直接 `getKey`→null→`initSign(null)`→
InvalidKeyException。该密钥**App 自己从不生成**（全程零 `generateKeyPair`），属外部预置。
`2304` 是本地构造（`body:null`），`/ts` 与 `/download` 均 HTTP 200。

混淆映射：`SignVerifyUtils` = `com.oplus.ota.downloader.util.b`，`ecdsaSignPki` = `b.d()`，
`getGkaReqDownloadType` = `b.i()`，`GetInfoThread` = `u7.a.run()`。
dex 里的 `...util.SignVerifyUtils` 是空壳（`ClassNotFoundException`）。
`b.g()` 返回 ~3200B base64 且每次内容不同 → 运行时生成的 CSR/证书请求体。

## 根因链（最终版，2026-09-24 真机验证）

```
cryptoeng_hidl: process com.oplus.ota have no permission calling cmd:10009 / 10013
CryptoengManager: commonGetResult: Cryptoeng Service return fail
  ↓
AttestationManager.packIdAttestation() -> false ; generateX509() -> null
  ↓（attestation 数据残缺，但私钥与签名本身没问题：initSign/sign 成功）
  ↓
服务端校验证书/attestation -> DownloadException mGKACode=2713
```

注：早期曾把 2713 解释为"新密钥未向服务端注册"，**该解释不完整，已作废**。
`sign()` 成功 ≠ attestation 成功。

## 密钥到底是谁造的（2026-09-24 r11 日志复核，重要）

**不是我们，也不是 App —— 是系统 Provider。**
`android.provider.BeandCupClalt.createApplicationPublicKey()` 造出密钥，
随后 `KeyStore#getKey("ota_pki_attest")` 真的返回 `AndroidKeyStoreECPrivateKey`。
我们的 `KeyRepair` 在这条链路上**从未生效**：`containsAlias -> false` 时正好在
SDK 的 attestation 流程内，只打了 `[Repair] deferring to SDK attestation flow`。
所以 r14 起 `ENABLE_KEY_REPAIR` / `ENABLE_KEY_INJECT` 均为 false，行为不变。

## gkaReq=2 认证链（源码级定稿，无需再查）

`com/oplus/ota/downloader/util/b.java` L54-84（被 hook 的 `b.a`）：
```
id  = MD5(getOpenid(context, GUID))          m(k(context))
ts  = GET ${component_update_url}/ts 的 body 解析成 long   p(context)
uri = URL path+query → 去掉首个 "/" → 所有 "=" 改成 ":"
ac  = OPLUS PKI attestation 证书链 Base64     (i9==2 → l(2).o())
as  = Base64(SHA256withECDSA(p5.b.t()))       d(bVar)
L78-81 → addRequestProperty: id / ts / ac / as
```
`p5/b.java:499` `t()` = `JSONObject{id,ts,uri}.toString()`（顺序 id→ts→uri）。

**两个静默回退（极易被忽略，日志里能一票否决）**：
- `/ts` 非 200 或 body 空 → `ts` 静默回退 `System.currentTimeMillis()`（`p()` L278-311）
- `getOpenid` 抛异常 → `id` 静默变成 `MD5("") = d41d8cd98f00b204e9800998ecf8427e`（`k()` L219-229）

`u7/a.java:69-73`：gka 头只在 `b.i(ctx)∈{1,2}` **且** `DownloadRequest.mDownloadType(w)∈{0,1}` 时才加。

## 2713 的定性（2026-09-24 只读源码分析，结论性）

**APK 内没有 2713 的任何定义/映射/文案。** 全树零命中。
它 = `u7/a.java:96`（及 `b7/b.java:127`）
`new JSONObject(body).optInt("responseCode", 2)` —— 服务端 body 字段的原样拷贝。
`mCode` 恒为 2（`EXCEPTION_SERVER_SUPPORT_CODE`），mGKACode = 2713 只被存进
`PackageListInfo.K`（`b7/e.java:59`）做持久化，没有任何 switch/提示。

**判据级要点：HTTP 206 = 成功，200 = 客户端判定「被拒绝」。**
`u7/a.java:78-96`：206 走分段下载；200 就把整个 body 当错误 JSON 解析并抛异常。
所以「/download HTTP 200」本身就等于服务端拒绝，2713 不是 HTTP status。

请求里客户端能决定的变量只有：URL（手动下载 = mManualUrl/f6261h）、
`userId="oplus-ota|"+OTA App versionCode`（**不是账号**）、
`marketName=Base64(ro.vendor.oplus.market.name)`、以及 `b.a()` 加的 id/ts/ac/as。
`b.a()` 还有个前置闸门：`DownloadRequest.mDownloadType`（`b7.d.w`）必须 ∈ {0,1}。

## 修复模式（当前工作重点）

`KeyRepair`：hook 点选在 `KeyStore#containsAlias` 返回 `false` 的那一刻生成 EC 密钥对
（AndroidKeyStore + KeyGenParameterSpec, EC/secp256r1, PURPOSE_SIGN, DIGEST_SHA256）。
时序上早于 `b.g()`（构造 CSR）和 `b.d()`（取私钥签名），一把钥匙补上全链路。

边界（务必守住）：**不改 containsAlias 返回值、不改任何参数/返回值/异常**（CI 只读
grep 门禁依旧通过）、**不跳过签名**，服务端照常验签。只补缺失的密钥材料。
能否下载成功取决于服务端是否接受新密钥的证书；若换别的错误码（非 2304）即为下一判据。

## 工作流约束（用户既有习惯）

- 本机不跑 Gradle（无 Android SDK）：改代码 → 推分支 → `gh run watch` → 真机装机验证。
- 分支名不能用斜杠（本机 git 写不了带斜杠的 ref）；commit/push 要在非沙箱模式下执行。
- 截图放 `screenshots/`，日志放 `logs/`；下载的构建产物放 `artifacts/`（已 gitignore）。

## 关键文件

`app/src/main/java/com/a23bc/oplus/otatracer/` 下：`HookEntry`（入口）、`ClassHunter`
（混淆兼容的类定位）、`OtaLog`（脱敏日志）、`TracerConfig`（目标常量）、
`SignVerifyTracer` / `GetInfoThreadTracer` / `DownloadExceptionTracer` /
`ResponseCodeTracer` / `KeyStoreTracer` / `SpTracer` / `LogTracer`。
