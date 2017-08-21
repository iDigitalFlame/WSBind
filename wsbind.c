#define _WIN32_WINNT 0x0501

#include <stdio.h>
#include <ws2tcpip.h>
#include <winsock2.h>
#include <windows.h>
#include <stdlib.h>
#include "wsbind_win.c"
#include "wsbind_key.c"
#include "wsbind_proc.c" 
#include "wsbind_comm.c"
#include "wsbind_shell.c" 
#include "wsbind_util.c"
#include "wsbind_const.c"

/*
 * WsBind Main
 */
int main(int argc, char *argv[])
{
    return 0;
}

/*
* WsBind Service Main
*/
void ServiceMain(int wsArgCount, char** wsArguments)
{
    return;
}

/*
 * WsBind DLLMain function
 */
BOOL WINAPI DllMain(HINSTANCE wsDLLHandle, DWORD wsReason, LPVOID wsReservedData)
{
    return TRUE;
}

/*
 * WsBind DLL Entry point
 */
__declspec(dllexport) void mopts(HWND wsHandle, HINSTANCE wsInstance, LPSTR wsArguments, int wsShowCmd) {}
