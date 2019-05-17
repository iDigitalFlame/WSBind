// Example C Code
// Windows
//

#define _WIN32_WINNT 0x0501

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

static BOOL haveLoadedFunctionsForFork(void);

int fork(void) {
    HANDLE hProcess = 0, hThread = 0;
    OBJECT_ATTRIBUTES oa = { sizeof(oa) };
    MEMORY_BASIC_INFORMATION mbi;
    CLIENT_ID cid;
    USER_STACK stack;
    PNT_TIB tib;
    THREAD_BASIC_INFORMATION tbi;

    CONTEXT context = { CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS | CONTEXT_FLOATING_POINT };

    if (setjmp(jenv) != 0) return 0; /* return as a child */

    /* check whether the entry points are
       initilized and get them if necessary */
    if (!ZwCreateProcess && !haveLoadedFunctionsForFork()) return -1;

    /* create forked process */
    ZwCreateProcess(&hProcess, PROCESS_ALL_ACCESS, &oa, NtCurrentProcess(), TRUE, 0, 0, 0);

    /* set the Eip for the child process to our child function */
    ZwGetContextThread(NtCurrentThread(), &context);

    /* In x64 the Eip and Esp are not present,
       their x64 counterparts are Rip and Rsp respectively. */
    #if _WIN64
        context.Rip = (ULONG)child_entry;
    #else
        context.Eip = (ULONG)child_entry;
    #endif

    #if _WIN64
        ZwQueryVirtualMemory(NtCurrentProcess(), (PVOID)context.Rsp, MemoryBasicInformation, &mbi, sizeof mbi, 0);
    #else
        ZwQueryVirtualMemory(NtCurrentProcess(), (PVOID)context.Esp, MemoryBasicInformation, &mbi, sizeof mbi, 0);
    #endif

    stack.FixedStackBase = 0;
    stack.FixedStackLimit = 0;
    stack.ExpandableStackBase = (PCHAR)mbi.BaseAddress + mbi.RegionSize;
    stack.ExpandableStackLimit = mbi.BaseAddress;
    stack.ExpandableStackBottom = mbi.AllocationBase;

    /* create thread using the modified context and stack */
    ZwCreateThread(&hThread, THREAD_ALL_ACCESS, &oa, hProcess, &cid, &context, &stack, TRUE);

    /* copy exception table */
    ZwQueryInformationThread(NtCurrentThread(), ThreadBasicInformation, &tbi, sizeof tbi, 0);
    tib = (PNT_TIB)tbi.TebBaseAddress;
    ZwQueryInformationThread(hThread, ThreadBasicInformation, &tbi, sizeof tbi, 0);
    ZwWriteVirtualMemory(hProcess, tbi.TebBaseAddress, &tib->ExceptionList, sizeof tib->ExceptionList, 0);

    /* start (resume really) the child */
    ZwResumeThread(hThread, 0);
    /* clean up */
    ZwClose(hThread);
    ZwClose(hProcess);

    /* exit with child's pid */
    return (int)cid.UniqueProcess;
}

static BOOL haveLoadedFunctionsForFork(void) {
    HANDLE ntdll = GetModuleHandle("ntdll");

    if (ntdll == NULL) return FALSE;

    //if (ZwCreateProcess && ZwQuerySystemInformation && ZwQueryVirtualMemory && ZwCreateThread && ZwGetContextThread && ZwResumeThread && ZwQueryInformationThread && ZwWriteVirtualMemory && ZwClose) {
     //   return TRUE;
    //}

    ZwCreateProcess = (ZwCreateProcess_t)GetProcAddress(ntdll, "ZwCreateProcess");
    ZwQuerySystemInformation = (ZwQuerySystemInformation_t)GetProcAddress(ntdll, "ZwQuerySystemInformation");
    ZwQueryVirtualMemory = (ZwQueryVirtualMemory_t)GetProcAddress(ntdll, "ZwQueryVirtualMemory");
    ZwCreateThread = (ZwCreateThread_t)GetProcAddress(ntdll, "ZwCreateThread");
    ZwGetContextThread = (ZwGetContextThread_t)GetProcAddress(ntdll, "ZwGetContextThread");
    ZwResumeThread = (ZwResumeThread_t)GetProcAddress(ntdll, "ZwResumeThread");
    ZwQueryInformationThread = (ZwQueryInformationThread_t)GetProcAddress(ntdll, "ZwQueryInformationThread");
    ZwWriteVirtualMemory = (ZwWriteVirtualMemory_t)GetProcAddress(ntdll, "ZwWriteVirtualMemory");
    ZwClose = (ZwClose_t)GetProcAddress(ntdll, "ZwClose");

    if (ZwCreateProcess && ZwQuerySystemInformation && ZwQueryVirtualMemory && ZwCreateThread && ZwGetContextThread && ZwResumeThread && ZwQueryInformationThread && ZwWriteVirtualMemory && ZwClose) {
        return TRUE;
    }
    else
    {
        ZwCreateProcess = NULL;
        ZwQuerySystemInformation = NULL;
        ZwQueryVirtualMemory = NULL;
        ZwCreateThread = NULL;
        ZwGetContextThread = NULL;
        ZwResumeThread = NULL;
        ZwQueryInformationThread = NULL;
        ZwWriteVirtualMemory = NULL;
        ZwClose = NULL;
    }
    return FALSE;
}

int main(int argc, char **argv)
{
    printf("Test!\n");
    return 0;
}
