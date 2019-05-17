#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct _MONITOR {
    BOOL (WINAPI *pfnEnumPorts) (LPWSTR pName,DWORD Level, LPBYTE pPorts, DWORD cbBuf, LPDWORD pcbNeeded, LPDWORD pcReturned);
    BOOL (WINAPI *pfnOpenPort) (LPWSTR pName, PHANDLE pHandle);
    BOOL (WINAPI *pfnOpenPortEx) (LPWSTR pPortName, LPWSTR pPrinterName, PHANDLE pHandle, struct _MONITOR FAR *pMonitor);
    BOOL (WINAPI *pfnStartDocPort) (HANDLE hPort, LPWSTR pPrinterName, DWORD JobId, DWORD Level, LPBYTE pDocInfo);
    BOOL (WINAPI *pfnWritePort) (HANDLE hPort, LPBYTE pBuffer, DWORD cbBuf, LPDWORD pcbWritten);
    BOOL (WINAPI *pfnReadPort) (HANDLE hPort, LPBYTE pBuffer, DWORD cbBuffer, LPDWORD pcbRead);
    BOOL (WINAPI *pfnEndDocPort) (HANDLE hPort);
    BOOL (WINAPI *pfnClosePort) (HANDLE hPort);
    BOOL (WINAPI *pfnAddPort) (LPWSTR pName, HWND hWnd, LPWSTR pMonitorName);
    BOOL (WINAPI *pfnAddPortEx) (LPWSTR pName, DWORD Level, LPBYTE lpBuffer, LPWSTR lpMonitorName);
    BOOL (WINAPI *pfnConfigurePort) (LPWSTR pName, HWND hWnd, LPWSTR pPortName);
    BOOL (WINAPI *pfnDeletePort) (LPWSTR pName, HWND hWnd, LPWSTR pPortName);
    BOOL (WINAPI *pfnGetPrinterDataFromPort) (HANDLE hPort,DWORD ControlID, LPWSTR pValueName, LPWSTR lpInBuffer, DWORD cbInBuffer, LPWSTR lpOutBuffer, DWORD cbOutBuffer,LPDWORD lpcbReturned);
    BOOL (WINAPI *pfnSetPortTimeOuts)(HANDLE hPort, LPCOMMTIMEOUTS lpCTO, DWORD reserved);
} MONITOR, FAR *LPMONITOR;
typedef struct _MONITOREX {
    DWORD    dwMonitorSize;
    MONITOR  Monitor;
} MONITOREX, FAR *LPMONITOREX;

BOOL WINAPI fG(HANDLE hPort) { return TRUE; }
BOOL WINAPI fF(HANDLE hPort) { return TRUE; }
BOOL WINAPI fB(LPWSTR pName, PHANDLE pHandle) { return TRUE; }
BOOL WINAPI fK(LPWSTR	pName,HWND hWnd, LPWSTR pPortName) { return TRUE; }
BOOL WINAPI fH(LPWSTR pName, HWND hWnd, LPWSTR pMonitorName) { return TRUE; }
BOOL WINAPI fJ(LPWSTR pName, HWND hWnd, LPWSTR pPortName) { return TRUE; }
BOOL WINAPI fE(HANDLE hPort, LPBYTE pBuffer, DWORD cbBuf, LPDWORD pcbRead) { return TRUE; }
BOOL WINAPI fD(HANDLE hPort, LPBYTE pBuffer, DWORD cbBuf, LPDWORD pcbWritten) { return TRUE; }
BOOL WINAPI fI(LPWSTR pName, DWORD Level, LPBYTE pBuffer, LPWSTR pMonitorName) { return TRUE; }
BOOL WINAPI fC( HANDLE hPort, LPWSTR pPrinterName, DWORD JobId, DWORD Level, LPBYTE pDocInfo) { return TRUE; }
BOOL WINAPI fA(LPWSTR pName, DWORD dwLevel, LPBYTE pPorts, DWORD cbBuf, LPDWORD pdwNeeded, LPDWORD pdwReturned) { return TRUE; }

MONITOREX MonitorEx = {
    sizeof(MONITOR), { fA, fB, NULL, fC, fD, fE, fF, fG, fH, fI, fJ, fK, NULL, NULL}
};

LPMONITOREX WINAPI InitializePrintMonitor(LPWSTR pRegistryRoot) {
	return &MonitorEx;
}
BOOL APIENTRY DllMain(HINSTANCE hModule, DWORD dwReason, LPVOID lpRes) {
	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
        return TRUE;
	case DLL_THREAD_ATTACH:
        return TRUE;
	case DLL_PROCESS_DETACH:
        return TRUE;
	case DLL_THREAD_DETACH:
        return TRUE;
    }
	return TRUE;
}