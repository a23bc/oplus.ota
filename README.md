# OplusOtaTracer

`com.oplus.ota` 下载流程的**纯诊断** LSPosed 模块。

点击「下载内部测试包」后出现

```
SignVerifyUtils: ecdsaSignPki exception: No installed provider supports this key: (null)
... DownloadException ... responseCode=2304
```

本模块默认只把这条链路上发生的事情**原样记录下来**：不改 OTA 行为、不绕过签名、
不改完整性/权限/服务器校验结果。

修复模式（`TracerConfig.ENABLE_KEY_REPAIR`，默认开）在此基础上多做一件事：当 App 自己
发现 `ota_pki_attest` 不存在时，补生成一把 EC 密钥。见下方「修复模式」。

## 只读保证

- 没有任何 hook 调用 `param.setResult()`、修改 `param.args`、或设置/清除 throwable。
  CI 里有一条 `Verify hooks are read-only` 步骤用 grep 强制这一点，出现即构建失败。
- 找不到类或方法时只记录一次，然后放弃，不会让 OTA App 崩溃。
- 只在 `com.oplus.ota`（含 `com.oplus.ota:ui` 进程）内安装 hook，其他包完全不碰。

## 脱敏规则

打印的内容只有：类名、类型、长度、null 状态、单向摘要（sha256 前 8 位）。

| 对象 | 打印方式 |
|---|---|
| `java.security.Key` | class / algorithm / format / encodedLen（`null` 本身即线索） |
| `byte[]` | `byte[64]`（无内容） |
| `char[]`（口令） | `char[n]`（无内容） |
| `String` | `len` + shape(numeric/hex/base64ish/text) + sha256 摘要 |
| URL | scheme://host/path + query **参数名**，不含参数值 |
| 未知对象 | 只打印 class name，绝不 `toString()` |

私钥、签名原文、token、密码一律不打印。

## 安装

1. 从 Actions 产物下载 release APK（或本地构建），安装。
2. LSPosed → 模块 → 勾选 **OplusOtaTracer** → 作用域勾选 **com.oplus.ota** → 重启（软重启即可）。
3. `adb logcat -s OplusOtaTracer` 或 `adb logcat | grep OplusOtaTracer`。
4. 打开 OTA，点「下载内部测试包」，复现。

## 日志格式

```
seq=17 t=+1234ms [SignVerify] ecdsaSignPki enter
seq=18 t=+1234ms [SignVerify] ecdsaSignPki argCount=3
seq=19 t=+1234ms [SignVerify] ecdsaSignPki arg[0] type=java.lang.String
seq=20 t=+1235ms [SignVerify] arg[0] String(len=8,shape=numeric,sha256:1f2e3d4c)
seq=21 t=+1235ms [SignVerify] key index=1 Key class=... algorithm=EC format=PKCS#8 encodedLen=null
seq=22 t=+1235ms [SignVerify] key null=false
seq=23 t=+1236ms [SignVerify] ecdsaSignPki exception:
seq=24 t=+1236ms [SignVerify] java.security.InvalidKeyException: No installed provider supports this key: (null)
...
seq=40 t=+1300ms [GetInfoThread] run threw
seq=41 t=+1300ms [DownloadException] mCode=...  mGKACode=...  msg=...  cause=...
seq=50 t=+1400ms [Response] responseCode=2304 url=https://.../ota/query?keys=[...]
```

`seq` 单调递增、`t` 是相对进程启动的毫秒数 —— 两者用来判断**先后顺序**。

## 诊断结论（已闭环，真机验证）

点击「下载内部测试包」失败的完整链路：

```
b.i()  getGkaReqDownloadType        -> 读 gka_req_download=2
b.a()  主流程
  ├─ /ts 请求                      -> HTTP 200
  ├─ b.g()  KeyStore.containsAlias("ota_pki_attest") -> false   <- 已知不存在
  │         返回 3204B base64 证书链 (b.h() -> Certificate[])
  └─ b.d()  ecdsaSignPki(p5.b)
       ├─ KeyStore.getKey("ota_pki_attest")        -> null
       ├─ Signature.getInstance("SHA256withECDSA")
       └─ initSign(null) -> InvalidKeyException:
          No installed provider supports this key: (null)
b.d() return ""  ->  b.a() return null
  -> GetInfoThread: download denied, response msg:{"body":null,"errMsg":"2304"}
  -> DownloadException mCode=2 mGKACode=2304
```

要点：

- **2304 不是 HTTP 状态码**，也不是服务端返回的。`/ts`、`/download` 两个请求都是 200，
  `body:null` 表明它是签名失败后**本地构造**的业务错误码。
- **根因**：AndroidKeyStore 中不存在 alias `ota_pki_attest` 的 EC 私钥。
  同进程 `ota_simple_key`（AES）能取到，KeyStore 本身正常。
- **该密钥不是 OTA 生成的**：全程没有任何 `KeyPairGenerator#generateKeyPair`
  调用（唯一的 `generateKey` 是 allawn 的数字信封 AES 密钥，与 PKI 无关）。
  它是外部预置的密钥对（带 attestation 证书链），OTA 只读取。
- **代码侧缺陷**：`containsAlias` 已经返回 `false`，却没有任何降级或重新申请分支，
  仍然继续 `getKey` → `null` → `initSign(null)`，异常被 catch 后返回空串。
- **有证书无私钥**：`b.g()` 拿到了 3204 字节证书链（`b.h()` 解析为 `Certificate[]`），
  但对应的私钥不在 KeyStore 里。

混淆映射（该 ROM 上）：`SignVerifyUtils` = `com.oplus.ota.downloader.util.b`，
`ecdsaSignPki` = `b.d()`，`getGkaReqDownloadType` = `b.i()`，`GetInfoThread` = `u7.a`。
dex 里的 `com.oplus.ota.downloader.util.SignVerifyUtils` 是个空壳
（`ClassNotFoundException`），只有它的内部类 `$ByteArrayComparator` 能加载。

## 修复模式

诊断结论指向一个具体的缺口：App 调 `containsAlias("ota_pki_attest")` 拿到 `false`，
然后拿着 `null` 去签名；而这把 EC 密钥**它自己从不生成**（全程无 `generateKeyPair`）。

修复模式在 App 自己发现 alias 缺失的那一刻，补做这个漏掉的步骤：

```java
KeyPairGenerator.getInstance("EC", "AndroidKeyStore")
    .initialize(new KeyGenParameterSpec.Builder(alias, PURPOSE_SIGN)
        .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
        .setDigests(DIGEST_SHA256).build())
    .generateKeyPair();
```

**这不是绕过签名**，三条边界守得很死：

1. 不改 `containsAlias` 的返回值（它仍然返回 `false`）；
2. 不改任何参数、返回值、异常 —— CI 的只读 grep 门禁依旧通过；
3. 不跳过签名。`b.d()` 照常 `getKey` → `Signature.initSign` → 服务端照常验签，
   只是这次私钥真的存在。

覆盖范围也刻意收窄：只处理 `TracerConfig.REPAIR_ALIASES` 里列明的 alias，
只在 App 自己刚确认缺失时触发，每进程每个 alias 只做一次，失败只记日志。

**能否下载成功取决于服务端**：它会校验证书链。若接受新密钥的证书，链路走通；
若要求 Google/OPPO 签发的 attestation，会返回别的错误码（不再是 2304）——
那个错误码本身就是下一步的判据。

## 监控点

| scope | 目标 | 抓什么 |
|---|---|---|
| `SignVerify` | `SignVerifyUtils.getGkaReqDownloadType()` / `ecdsaSignPki()` | 入参、Key 类型/algorithm/format/null、返回值、异常与栈 |
| `GetInfoThread` | `GetInfoThread.run()` + 名字含 download/request/gka/http/url/response 的方法 | 请求开始/返回、denied、异常 |
| `DownloadException` | 全部构造函数 | mCode / mGKACode / msg / cause + 构造点栈 |
| `Response` | `HttpURLConnectionImpl#getResponseCode`、okhttp `Response#code` | responseCode 是否真的来自服务端 |
| `KeyStore` | `KeyStore.getInstance/load/getKey/getEntry`、`KeyPairGenerator`、`Signature` | 是否用了 AndroidKeyStore，Key 从哪来 |
| `Prefs` | `SharedPreferencesImpl#getInt` | gakReqSpValue 的读写上下文 |
| `AppLog` | App 自身 Log（关键词过滤） | "download denied" 等原始日志 |

不做全包方法 hook：`SignVerify` 只 hook 4 个名字，`GetInfoThread` 每类上限 12 个方法，
`KeyStore`/`Response`/`Prefs` 只 hook 具名入口点且带调用栈过滤。

## 混淆兼容

类名靠三条路径定位，全部安全失败：

1. `TracerConfig` 里的 FQCN 猜测（未混淆 ROM 的快路径，启动即解析）；
2. 启动 3s 后的**关键词 dex 扫描**（后台线程，按类名关键词命中才 `Class.forName`）；
3. 启动 9s 后的**深度扫描**兜底（后台线程：加载 `com.oplus.ota` 下的类，按
   `ecdsaSignPki` / `getGkaReqDownloadType` 等**方法名**匹配；限流 60 个/批、
   总预算 15s；若路径 1、2 已命中 `SignVerifyUtils` 则跳过）。

> 曾经有一版 hook 了 `ClassLoader#loadClass`，在回调里调 `getDeclaredMethods()`
> 做方法名匹配。结果：嵌套类加载 → 应用 ClassLoader 损坏（连 `android.util.Log`
> 都 `ClassNotFoundError`）→ `:ui` 进程黑屏。**类加载本身绝不再 hook**，所有反射
> 只在后台线程做。

## 黑屏 / 卡死排查

装完如果 OTA 界面起不来：

1. 先恢复现场（任选其一）：
   - `adb uninstall com.a23bc.oplus.otatracer`
   - LSPosed 里取消勾选模块（或开机时按音量键进 LSPosed 安全模式）
2. 看日志最后一行停在哪 —— 启动后每 5s 有一条 `[Boot] heartbeat left=N rulesHit=[...]`
   心跳（共 12 条 / 60s）。心跳停止的 seq 就是卡死点。
3. 二分定位：`TracerConfig` 里有三个开关，改成 `false` 重新编译即可逐项排除
   - `ENABLE_SHARED_CLASS_HOOKS` —— HttpURLConnection / KeyStore / SharedPreferences / Log
   - `ENABLE_LOG_ECHO` —— 只关 Log 回声
   - `ENABLE_DEX_SCAN` —— 只关后台 dex 扫描

## 编译

本机不跑 Gradle（无 Android SDK）。推分支后由 Actions 构建：

```
git push origin <branch>
gh run watch
```

CI 流程：下载 Gradle 8.2 + runner 自带 Android SDK → 只读性 grep 检查 →
`compileDebugJavaWithJavac` → `assembleRelease` → 校验 `assets/xposed_init` 已打进 APK。

## 文件

```
app/src/main/java/com/a23bc/oplus/otatracer/
  HookEntry.java              入口，包过滤
  OtaLog.java                 统一 TAG + 脱敏 + 分块
  TracerConfig.java           目标类名 / 方法名 / 关键词
  ClassHunter.java            类定位（FQCN / loadClass / dex 扫描）
  SignVerifyTracer.java       SignVerifyUtils
  GetInfoThreadTracer.java    GetInfoThread
  DownloadExceptionTracer.java DownloadException
  ResponseCodeTracer.java     响应码来源
  KeyStoreTracer.java         KeyStore / AndroidKeyStore 参与情况
  SpTracer.java               gakReqSpValue 上下文
  LogTracer.java              App 自身日志回声
```
