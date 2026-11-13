# Nutcracker 待办与优化清单 (Backlog & Roadmap)

本项目在自动化测试回归与沙箱实测过程中，梳理出以下待优化事项。本文档记录了**已完成的修复项**以及**剩余 4 个待深入优化的技术点**与具体实施方案，供后续迭代推进。

---

## ✅ 已完成优化

- [x] **1. 端口与数据文件硬编码修复，实现零污染测试隔离**
  - **完成时间**：2026-11-13
  - **对应提交**：`e1e3d94`, `9ee32bf`
  - **核心成果**：
    - Python 服务端实现 `get_vault_file()`、`get_vault_dir()`、`get_configured_port()` 动态获取与 CLI 参数扩展（`--port`, `--vault-file`, `--vault-dir`, `--no-browser`）。
    - Tauri Rust 原生内核增加 `NUTCRACKER_VAULT_FILE` 与 `NUTCRACKER_VAULT_DIR` 拦截与单测覆盖。
    - 测试框架引入 `find_free_port()` 动态申请空闲端口，新增 `test_00_port_and_vault_isolation` 断言，确保 100% 不触碰生产金库 `~/.nutcracker/vault.enc`。

---

## 📌 待优化清单 (Next Iterations)

### 2. Linux 无头沙箱 / CI 环境智能无头探测 (Headless Auto-Detection)

- **当前现状**：
  - 目前仅依赖显式传递环境变量 `NUTCRACKER_NO_BROWSER=1` 或 CLI 参数 `--no-browser` 来阻止启动时调用系统浏览器。
  - 在无头 Linux 服务器（如通过 SSH 连接）、Docker 容器或 CI 运行环境下，如果未传入该变量，后台线程仍会尝试调用 `open`/浏览器命令，产生警告或挂起。
- **优化方案**：
  1. **环境特征自动识别**：
     - 检测系统环境变量：当非 macOS 且 `DISPLAY` 与 `WAYLAND_DISPLAY` 均为空时，自动判断为无头环境。
     - 识别常见 CI 环境变量（如 `CI=true`、`GITHUB_ACTIONS=true`、`GITLAB_CI` 等）。
     - 检测是否在无 TTY 管道中运行（`not sys.stdin.isatty()`）。
  2. **优雅降级**：
     - 在判定为无头环境时，自动跳过 `open_browser()`，并在控制台友好输出：
       `"Headless environment detected. Serving API at http://localhost:<port> without GUI."`
  3. **参数统一**：
     - 支持 `--headless` 作为 `--no-browser` 的常用别名。
- **涉及模块**：[`src/server.py`](src/server.py)
- **优先级**：P2（中）

---

### 3. API 错误契约标准化与错误码机制 (Standardized API Error Codes)

- **当前现状**：
  - 当前前后端与测试断言主要依赖字符串匹配（例如断言 `'Wrong master password'` 是否包含在 `res['error']` 中）。
  - 若未来进行中英文国际化（i18n）或文案微调，基于硬编码字符串的判定容易被意外破坏。
- **优化方案**：
  1. **引入结构化错误代码**：
     - 统一响应格式：
       ```json
       {
         "ok": false,
         "code": "AUTH_FAILED",
         "error": "Wrong master password or corrupted vault."
       }
       ```
     - 定义规范的错误枚举常量：
       - `AUTH_FAILED`：主密码解密认证失败（Auth Tag 校验未通过）
       - `VAULT_CORRUPTED`：金库数据过短或头部 Magic 损毁
       - `VAULT_NOT_FOUND`：金库文件尚未初始化
       - `INVALID_ARGUMENT`：参数缺失或格式不合法
  2. **Tauri Rust 端强类型错误枚举**：
     - 在 Rust 端定义 `enum VaultError` 并实现 `serde::Serialize`，与 Python HTTP 返回的 `code` 严格镜像对齐。
  3. **前端对齐**：
     - `src/renderer/app.js` 优先依据 `res.code` 触发对应 UI 状态处理，提升容错能力。
- **涉及模块**：[`src/server.py`](src/server.py), [`src-tauri/src/main.rs`](src-tauri/src/main.rs), [`src/renderer/app.js`](src/renderer/app.js), [`tests/test_server_api.py`](tests/test_server_api.py)
- **优先级**：P2（中）

---

### 4. 跨平台 Cargo / Rust 工具链自适应探测 (Robust Toolchain Discovery)

- **当前现状**：
  - `tests/test_cross_compatibility.py` 中通过检查 `shutil.which("cargo")` 和硬编码的 `~/.cargo/bin/cargo` 来探测 Cargo 二进制文件。
  - 在使用 `rustup` 自定义根目录、`asdf` / `mise` 多版本管理器、Windows 环境或特定容器镜像（如 `$CARGO_HOME` 非标准路径）时，仍存在工具链漏检可能。
- **优化方案**：
  1. **动态支持 `$CARGO_HOME`**：
     - 优先读取 `os.environ.get("CARGO_HOME")`，在其下的 `bin/cargo` 寻找可执行文件。
  2. **多探测路径候选列表**：
     - 遍历候选路径：`$CARGO_HOME/bin`、`~/.cargo/bin`、`~/.local/share/cargo/bin`、`/usr/local/bin`、`/opt/homebrew/bin`。
  3. **清晰的引导输出**：
     - 当检测不到 Cargo 时，除调用 `self.skipTest` 外，在终端给出清晰的操作指引（如 `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`），提升开发者调试体验。
- **涉及模块**：[`tests/test_cross_compatibility.py`](tests/test_cross_compatibility.py)
- **优先级**：P3（低）

---

### 5. 内存安全深度防御与加解密模糊测试 (Memory Zeroization & Cryptographic Fuzzing)

- **当前现状**：
  - 核心密码学算法已在 Python 与 Rust 之间实现 100% 互通，并补充了单字节防篡改、固定向量与 UTF-8 边界测试。
  - 面对极致安全场景（如冷启动内存 dump 分析、异常畸形 Payload 注入），尚可进一步加固。
- **优化方案**：
  1. **敏感内存清零机制 (Zeroize)**：
     - 在 Rust 原生层引入 `zeroize` crate，确保主密码字符串（`password`）与 PBKDF2 派生的 32 字节对称密钥（`key`）在函数作用域结束时主动将内存重写为 0，防止敏感信息驻留交换空间或内存转储中。
  2. **模糊测试 (Fuzz Testing)**：
     - 引入 `cargo-fuzz` 或 `libfuzzer` 对 `decrypt()` 函数进行自动化模糊变异测试，确保面对任意损坏的字节流均能优雅返回 `Err`，绝不触发未捕获的 Panic 或内存段错误。
  3. **大规模数据集压力测试**：
     - 增加专项测试用例，模拟包含 5,000+ 条 API Key 的大型金库在执行“主密码修改 / 批量加密”时的重加密耗时与原子写入稳定性。
- **涉及模块**：[`src-tauri/Cargo.toml`](src-tauri/Cargo.toml), [`src-tauri/src/main.rs`](src-tauri/src/main.rs), [`tests/test_crypto.py`](tests/test_crypto.py)
- **优先级**：P2（中）

---

## 🎯 迭代推进节奏建议

| 优化项 | 推荐版本 | 预计工时 | 依赖与影响 |
|:---|:---|:---|:---|
| **#2 无头环境自动探测** | v0.1.1 | 0.5 天 | 仅改动 `server.py`，无破坏性影响 |
| **#3 API 错误码标准化** | v0.1.1 | 1 天 | 需联动前端 `app.js` 与单测更新 |
| **#4 Cargo 路径自适应** | v0.1.1 | 0.5 天 | 仅改动测试脚本 |
| **#5 内存清零与 Fuzz** | v0.2.0 | 1.5 天 | 涉及 Rust 依赖添加与底层内存处理 |
