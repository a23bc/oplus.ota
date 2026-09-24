# oplus.ota 项目长期约定

## 项目性质

`com.oplus.ota`（OPPO/一加 OTA）下载流程的**纯诊断** LSPosed 模块。
目标问题：点击「下载内部测试包」出现 `ecdsaSignPki exception: No installed provider
supports this key: (null)` 及后续 `DownloadException` / `responseCode=2304`。

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

## 工作流约束（用户既有习惯）

- 本机不跑 Gradle（无 Android SDK）：改代码 → 推分支 → `gh run watch` → 真机装机验证。
- 分支名不能用斜杠（本机 git 写不了带斜杠的 ref）；commit/push 要在非沙箱模式下执行。
- 截图放 `screenshots/`，日志放 `logs/`；下载的构建产物放 `artifacts/`（已 gitignore）。

## 关键文件

`app/src/main/java/com/a23bc/oplus/otatracer/` 下：`HookEntry`（入口）、`ClassHunter`
（混淆兼容的类定位）、`OtaLog`（脱敏日志）、`TracerConfig`（目标常量）、
`SignVerifyTracer` / `GetInfoThreadTracer` / `DownloadExceptionTracer` /
`ResponseCodeTracer` / `KeyStoreTracer` / `SpTracer` / `LogTracer`。
