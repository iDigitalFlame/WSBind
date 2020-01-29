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