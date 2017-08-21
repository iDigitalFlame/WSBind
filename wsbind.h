#define _WIN32_WINNT 0x0501

#include <winsock2.h>
#include <ws2tcpip.h>
#include <ctype.h>
#include <iphlpapi.h>

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

#include "wsbind_const.c"
#include "wsbind_comm.c"

#include <psapi.h>
#include <tlhelp32.h>

#include "wsbind_util.c"
#include "wsbind_win.c"
#include "wsbind_key.c"
#include "wsbind_proc.c"
#include "wsbind_shell.c"