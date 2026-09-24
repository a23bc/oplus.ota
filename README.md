# OplusOtaTracer

`com.oplus.ota` 下载流程的**纯诊断** LSPosed 模块。

点击「下载内部测试包」后出现

```
SignVerifyUtils: ecdsaSignPki exception: No installed provider supports this key: (null)
... DownloadException ... responseCode=2304
```

本模块只负责把这条链路上发生的事情**原样记录下来**。它不改 OTA 行为、不绕过签名、
不改完整性/权限/服务器校验结果。

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

1. `TracerConfig` 里的 FQCN 猜测（未混淆 ROM 的快路径）；
2. `ClassLoader#loadClass` hook —— 类被链接时按**方法名**特征匹配（`ecdsaSignPki`、
   `getGkaReqDownloadType` 这类名字通常不参与混淆）；
3. 启动 1.5s 后的 dex 扫描兜底（按类名关键词 + 方法特征，命中才 `Class.forName`）。

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
