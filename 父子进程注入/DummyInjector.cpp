#include <windows.h>
#include <stdio.h>

//在子进程创建挂起时注入dll
//hProcess      被创建时挂起的进程句柄
//hThread       进程中被挂起的线程句柄
//szDllPath     被注入的dll的完整路径
typedef DWORD64 qw;

#ifdef _WIN64
BOOL StartHook(HANDLE hProcess, HANDLE hThread, TCHAR* szDllPath)
{
    BYTE ShellCode[70 +1 + MAX_PATH * sizeof(TCHAR)] =
    {
        0x50,               //push rax   保存rax
        0x51,               //push rcx   保存rcx
        0x52,               //push rdx   保存rdx
        0x48,0xB9,0xCC, 0xCC ,0xCC ,0xCC ,0xCC ,0xCC ,0xCC ,0xCC,   //mov rcx, 0xCCCCCCCCCCCCCCCC(xxxxxxxx的偏移为5)
        0x48,0xB8,0xCC, 0xCC ,0xCC ,0xCC ,0xCC ,0xCC ,0xCC ,0xCC,  //mov rax, 0xCCCCCCCCCCCCCCCC([addr]的偏移为15)
        0x48,0x8B,0x00, //mov rax, qword ptr ds:[rax]
        0x48, 0x83, 0xEC, 0x40, //sub rsp, 0x30           一般情况都是 rsp,0x28 即rcx,rdx,r8,r9再加个返回值,但是前面push了奇数次，堆栈要16字节对齐，所以0x28+0x8=0x30
        0xFF,0xD0, //call rax
        0x48, 0x83, 0xC4, 0x40, //add rsp, 0x30           恢复堆栈
        0x5A,               //pop rdx
        0x59,               //pop rcx
        0x58,               //pop rax
        0x48,0xB8,0xCC, 0xCC ,0xCC ,0xCC ,0xCC ,0xCC ,0xCC ,0xCC,  //mov rax, 0xCCCCCCCCCCCCCCCC([eip]的偏移为41)
        0x48,0x8B,0x00, //mov rax, qword ptr ds:[rax]
        0xFF, 0xE0, //jmp rax
        0xCC, 0xCC ,0xCC ,0xCC ,0xCC ,0xCC ,0xCC ,0xCC,        //保存loadlibraryW函数的地址(偏移为54)
        0xCC, 0xCC ,0xCC ,0xCC ,0xCC ,0xCC ,0xCC ,0xCC,        //保存创建进程时被挂起的线程RIP(偏移为62)
        0,              //保存dll路径字符串(偏移为70)
    };
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_ALL;
    if (!GetThreadContext(hThread, &ctx))
    {
        printf("GetThreadContext() ErrorCode:[0x%llx]\n", GetLastError());
        return FALSE;
    }
    //在目标进程内存空间调拨一块可执行的内存
    LPVOID LpAddr = VirtualAllocEx(hProcess, NULL, 70 +1 + MAX_PATH * sizeof(TCHAR), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (LpAddr == NULL)
    {
        printf("VirtualAllocEx() ErrorCode:[0x%llx]\n", GetLastError());
        return FALSE;
    }
    //获得LoadLibraryW函数的地址
    qw LoadDllAAddr = (qw)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");
    if (LoadDllAAddr == NULL)
    {
        printf("GetProcAddress() ErrorCode:[0x%llx]\n", GetLastError());
        return FALSE;
    }
    printf("原始RIP=0x%llx\n", ctx.Rip);


    //写入dllpath
    memcpy((char*)(ShellCode + 70), szDllPath, MAX_PATH);
    //写入push xxxxxxxx
    *(qw*)(ShellCode + 5) = (qw)LpAddr + 70;
    //写入loadlibraryA地址
    *(qw*)(ShellCode + 54) = (qw)LoadDllAAddr;
    //写入call [addr]的[addr]
    *(qw*)(ShellCode + 15) = (qw)LpAddr + 54;
    //写入原始rip
    *(qw*)(ShellCode + 62) = ctx.Rip;
    //写入jmp [eip]的[eip]
    *(qw*)(ShellCode + 41) = (qw)LpAddr + 62;
    //把shellcode写入目标进程


    if (!WriteProcessMemory(hProcess, LpAddr, ShellCode, 70 + 1 + MAX_PATH * sizeof(TCHAR), NULL))
    {
        printf("WriteProcessMemory() ErrorCode:[0x%llx]\n", GetLastError());
        return FALSE;
    }
    //修改目标进程的EIP，执行被注入的代码
    ctx.Rip = (qw)LpAddr;
    if (!SetThreadContext(hThread, &ctx))
    {
        printf("SetThreadContext() ErrorCode:[0x%llx]\n", GetLastError());
        return FALSE;
    }
    printf("修改后Rip=0x%llx\n", ctx.Rip);
    return TRUE;
};
#else
BOOL StartHook(HANDLE hProcess, HANDLE hThread, TCHAR* szDllPath)
{
    BYTE ShellCode[30 + MAX_PATH * sizeof(TCHAR)] =
    {
        0x60,               //pushad
        0x9c,               //pushfd
        0x68,0xaa,0xbb,0xcc,0xdd,   //push xxxxxxxx(xxxxxxxx的偏移为3)
        0xff,0x15,0xdd,0xcc,0xbb,0xaa,  //call [addr]([addr]的偏移为9)
        0x9d,               //popfd
        0x61,               //popad
        0xff,0x25,0xaa,0xbb,0xcc,0xdd,  //jmp [eip]([eip]的偏移为17)
        0xaa,0xaa,0xaa,0xaa,        //保存loadlibraryW函数的地址(偏移为21)
        0xaa,0xaa,0xaa,0xaa,        //保存创建进程时被挂起的线程EIP(偏移为25)
        0,              //保存dll路径字符串(偏移为29)
    };
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_ALL;
    if (!GetThreadContext(hThread, &ctx))
    {
        printf("GetThreadContext() ErrorCode:[0x%08x]\n", GetLastError());
        return FALSE;
    }
    //在目标进程内存空间调拨一块可执行的内存
    LPVOID LpAddr = VirtualAllocEx(hProcess, NULL, 30 + MAX_PATH * sizeof(TCHAR), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (LpAddr == NULL)
    {
        printf("VirtualAllocEx() ErrorCode:[0x%08x]\n", GetLastError());
        return FALSE;
    }
    //获得LoadLibraryW函数的地址
    DWORD LoadDllAAddr = (DWORD)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");
    if (LoadDllAAddr == NULL)
    {
        printf("GetProcAddress() ErrorCode:[0x%08x]\n", GetLastError());
        return FALSE;
    }
    printf("原始EIP=0x%08x\n", ctx.Eip);
    //写入dllpath
    memcpy((char*)(ShellCode + 29), szDllPath, MAX_PATH);
    //写入push xxxxxxxx
    *(DWORD*)(ShellCode + 3) = (DWORD)LpAddr + 29;
    //写入loadlibraryA地址
    *(DWORD*)(ShellCode + 21) = LoadDllAAddr;
    //写入call [addr]的[addr]
    *(DWORD*)(ShellCode + 9) = (DWORD)LpAddr + 21;
    //写入原始eip
    *(DWORD*)(ShellCode + 25) = ctx.Eip;
    //写入jmp [eip]的[eip]
    *(DWORD*)(ShellCode + 17) = (DWORD)LpAddr + 25;
    //把shellcode写入目标进程
    if (!WriteProcessMemory(hProcess, LpAddr, ShellCode, 30 + MAX_PATH * sizeof(TCHAR), NULL))
    {
        printf("WriteProcessMemory() ErrorCode:[0x%08x]\n", GetLastError());
        return FALSE;
    }
    //修改目标进程的EIP，执行被注入的代码
    ctx.Eip = (DWORD)LpAddr;
    if (!SetThreadContext(hThread, &ctx))
    {
        printf("SetThreadContext() ErrorCode:[0x%08x]\n", GetLastError());
        return FALSE;
    }
    printf("修改后EIP=0x%08x\n", ctx.Eip);
    return TRUE;
};
#endif

int main()
{
    STARTUPINFO sti;
    PROCESS_INFORMATION proci;
    memset(&sti, 0, sizeof(STARTUPINFO));
    memset(&proci, 0, sizeof(PROCESS_INFORMATION));
    sti.cb = sizeof(STARTUPINFO);

#ifdef _WIN64
    wchar_t ExeName[MAX_PATH] = L"E:\\Injector\\Client64.exe";//子进程的名字及启动参数
    wchar_t DllName[MAX_PATH] = L"E:\\Injector\\HiJack64.dll";//被注入的dll的完整路径
#else
    wchar_t ExeName[MAX_PATH] = L"E:\\Injector\\Client32.exe";//子进程的名字及启动参数
    wchar_t DllName[MAX_PATH] = L"E:\\Injector\\HiJack32.dll";//被注入的dll的完整路径
#endif

    if (CreateProcess(NULL, ExeName, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &sti, &proci) == NULL)
    {
        printf("CreateProcess() ErrorCode:[0x%llx]\n", GetLastError());
        getchar();
        return 0;
    }
    if (!StartHook(proci.hProcess, proci.hThread, DllName))
    {
        TerminateProcess(proci.hProcess, 0);
        printf("Terminated Process\n");
        getchar();
        return 0;
    }
    ResumeThread(proci.hThread);
    CloseHandle(proci.hProcess);
    CloseHandle(proci.hThread);
    getchar();
    return 0;
}


