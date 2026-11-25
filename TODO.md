# Nutcracker 待办与优化清单 (Backlog & Roadmap)

本项目在自动化测试回归与沙箱实测过程中，梳理出以下待优化事项。本文档记录了**所有已完成的修复与优化项**，供后续回顾与持续演进。

---

## ✅ 已完成优化

- [x] **1. 端口与数据文件硬编码修复，实现零污染测试隔离**
  - **完成时间**：2026-11-13
  - **对应提交**：`e1e3d94`, `9ee32bf`
  - **核心成果**：
    - Python 服务端实现 `get_vault_file()`、`get_vault_dir()`、`get_configured_port()` 动态获取与 CLI 参数扩展（`--port`, `--vault-file`, `--vault-dir`, `--no-browser`）。
    - Tauri Rust 原生内核增加 `NUTCRACKER_VAULT_FILE` 与 `NUTCRACKER_VAULT_DIR` 拦截与单测覆盖。
    - 测试框架引入 `find_free_port()` 动态申请空闲端口，新增 `test_00_port_and_vault_isolation` 断言，确保 100% 不触碰生产金库 `~/.nutcracker/vault.enc`。

- [x] **2. Linux 无头沙箱 / CI 环境智能无头探测与参数统一 (Headless Auto-Detection)**
  - **完成时间**：2026-11-17
  - **对应提交**：`8fe8a69`
  - **核心成果**：
    - Python 服务端实现 `is_headless()` 智能探测，自动识别无 GUI 显示服务器（非 macOS 且无 `DISPLAY`/`WAYLAND_DISPLAY`）、常见 CI 环境变量（`CI`、`GITHUB_ACTIONS`、`GITLAB_CI` 等）、非交互 TTY 管道（`not sys.stdin.isatty()`）以及显式配置。
    - 统一支持 `--headless` 作为 `--no-browser` 的常用 CLI 别名，并支持 `NUTCRACKER_HEADLESS` 环境变量。
    - 智能无头降级，控制台友好输出 `"Headless environment detected. Serving API at http://localhost:<port> without GUI."` 并跳过浏览器唤醒；同时扩充了跨平台（macOS / Linux `xdg-open` / `webbrowser`）桌面打开降级链。
    - 新增 `test_07_headless_auto_detection` 与 `test_08_cli_headless_flag_and_log` 自动化测试用例，回归测试套件扩展至 16 个用例。

- [x] **3. API 错误契约标准化与错误码机制 (Standardized API Error Codes)**
  - **完成时间**：2026-11-19
  - **核心成果**：
    - 统一错误返回结构：`{ "ok": false, "code": "...", "error": "..." }`，彻底消除基于纯字符串判定破坏的风险；
    - 规范错误枚举常量：`AUTH_FAILED`（认证解密失败）、`VAULT_CORRUPTED`（数据损坏或截断）、`VAULT_NOT_FOUND`（金库文件未找到）、`INVALID_ARGUMENT`（参数缺失或非法格式）、`INTERNAL_ERROR` 与 `UNKNOWN_ENDPOINT`；
    - Tauri Rust 原生内核定义强类型 `enum VaultError` 并实现 `serde::Serialize`、`Deref<Target = str>`、`Display` 与 `std::error::Error`，双端错误码完全镜像对齐且 100% 向后兼容；
    - 新增 `test_09_api_standardized_error_codes` 与 `test_vault_error_standardized_contract` 自动化测试用例，回归测试套件扩展至 17 个用例（Rust 原生 9 个用例）。

- [x] **4. 跨平台 Cargo / Rust 工具链自适应探测 (Robust Toolchain Discovery)**
  - **完成时间**：2026-11-25
  - **核心成果**：
    - `tests/test_cross_compatibility.py` 实现 `get_cargo_fallback_dirs()`、`discover_cargo_binary()` 与 `format_cargo_missing_guidance()`。
    - 优先探测 `$CARGO_HOME/bin` 与 `PATH`，并遍历 `~/.cargo/bin`、`$XDG_DATA_HOME/cargo/bin`、`~/.local/share/cargo/bin`、`~/.asdf/shims`、`~/.local/share/mise/shims`、`/opt/homebrew/bin`、`/usr/local/bin` 及 Windows `%USERPROFILE%\.cargo\bin`；同时在调用 `cargo test` 时自动将探测到的工具链 `bin` 目录注入子进程 `PATH`，避免沙箱环境漏检 `rustc`。
    - 当未检测到 Cargo 时输出清晰的 `rustup` 安装命令与 `CARGO_HOME`/`PATH` 配置指引后优雅跳过。
    - 新增 `TestCargoToolchainDiscovery` 3 项自动化单元测试，回归测试套件扩展至 20 个用例。

- [x] **5. 内存安全深度防御与加解密模糊测试 (Memory Zeroization & Cryptographic Fuzzing)**
  - **完成时间**：2026-11-25
  - **核心成果**：
    - 在 [`src-tauri/Cargo.toml`](src-tauri/Cargo.toml) 引入 `zeroize` crate（`v1.9`），将密码学核心模块抽离至 [`src-tauri/src/crypto.rs`](src-tauri/src/crypto.rs) 并通过 [`src-tauri/src/lib.rs`](src-tauri/src/lib.rs) 暴露；
    - `derive_key()` 返回 `Zeroizing<[u8; 32]>`，[`src-tauri/src/main.rs`](src-tauri/src/main.rs) 中各 Tauri 命令对 `password`、`old_password`、`new_password` 及加解密中间明文 JSON 均采用 `Zeroizing<String>` 托管，并在 `decrypt()` UTF-8 解析失败时主动擦除解码缓冲区，确保敏感数据在作用域结束或异常返回时立即覆写清零；
    - 新增 [`src-tauri/fuzz/Cargo.toml`](src-tauri/fuzz/Cargo.toml) 与 [`src-tauri/fuzz/fuzz_targets/decrypt_fuzz.rs`](src-tauri/fuzz/fuzz_targets/decrypt_fuzz.rs) 标准 `cargo-fuzz` / `libfuzzer-sys` 目标，同时在 Rust 与 Python 单元测试中内置确定性畸形输入模糊测试（边界长度、全量截断/单比特变异、合法密文包裹非法 UTF-8）与 5,200+/5,500 条 API Key 大规模金库轮换及 `0600` 原子写入稳定性压力测试，全量回归套件扩展至 22 个用例（Rust 原生 12 个用例）。

---

## 🎯 迭代推进节奏建议

| 优化项 | 状态 | 推荐版本 | 预计工时 | 依赖与影响 |
|:---|:---:|:---|:---|:---|
| **#2 无头环境自动探测** | ✅ 已完成 | v0.1.1 | 0.5 天 | 仅改动 `server.py`，无破坏性影响 |
| **#3 API 错误码标准化** | ✅ 已完成 | v0.1.1 | 1 天 | 统一 Python 与 Rust 错误契约并扩充单测 |
| **#4 Cargo 路径自适应** | ✅ 已完成 | v0.1.1 | 0.5 天 | 仅改动测试脚本，扩充工具链探测单测 |
| **#5 内存清零与 Fuzz** | ✅ 已完成 | v0.2.0 | 1.5 天 | 引入 `zeroize`、`cargo-fuzz` 目标及 5,000+ 条目压测 |
