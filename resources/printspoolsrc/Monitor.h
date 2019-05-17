#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <winspool.h>
#include "winsplp.h"
#include <shlobj.h>
#include <limits.h>
#include <shlwapi.h>



BOOL WINAPI DllMain(
	HINSTANCE hModule, 
	DWORD  dwReason, 
	LPVOID lpRes);

BOOL WINAPI WaitForOutput(char *sPath, DWORD dwTimeout);

LPMONITOREX WINAPI InitializePrintMonitor(LPWSTR pRegistryRoot);

