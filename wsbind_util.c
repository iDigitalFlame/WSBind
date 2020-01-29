// WinSHock Binder (WsBind) Utilities Stub
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

typedef struct CHARBUFFER {
    int size;
    int buffsize;
    unsigned char* buffer;
} CharBuffer;

void wsu_clear_buffer(char** wsBuffer, int wsSize);

BOOL WS_RAND_INT = FALSE;

int wsu_randInt(int wsMin, int wsMax);

int wsu_randIntMax(int wsMax)
{
    return wsu_randInt(0, wsMax);
}
int wsu_randInt(int wsMin, int wsMax)
{
    if(!WS_RAND_INT)
    {
        srand(time(NULL));
        WS_RAND_INT = TRUE;
    }
    return wsMin + (rand() % (wsMax - wsMin));
}
void wsu_clear_buffer(char** wsBuffer, int wsSize)
{
    int wsStart = 0;
    for(; wsStart < wsSize; wsStart++) (*wsBuffer)[wsStart] = 0;
}
char* wsu_utf16_to_utf8(char* wsUTF16, int wsLength)
{
    char *wsReturn = calloc((wsLength/2)+1, 1);
    wsu_clear_buffer(&wsReturn, wsLength/2);
    int wsStart = 0;
    for(; wsStart < wsLength; wsStart += 2)
        wsReturn[wsStart/2] = wsUTF16[wsStart];
    wsReturn[(wsLength/2)] = 0;
    return wsReturn;
}
int wsu_index_of(char* wsStringFind, char* wsStringTarget)
{
    int wsLen1 = strlen(wsStringFind), wsLen2 = strlen(wsStringTarget);
    if(wsLen1 > wsLen2) return -1;
    int wsStartPos = -1, wsCurrentPos = 0, wsCur = 0;
    for(; wsCur < wsLen2 && wsCurrentPos < wsLen1; wsCur++)
    {
        if(wsStringTarget[wsCur] == wsStringFind[wsCurrentPos])
        {
            if(wsStartPos == -1)
            {
                wsStartPos = wsCur;
                wsCurrentPos = 1;
            }
            else
            {
                if((wsCurrentPos + 1) >= wsLen1) return wsStartPos;
                wsCurrentPos++;
            }
        }
        else
        {
            wsStartPos = -1;
            wsCurrentPos = 0;
        }
    }
    return -1;
}
char* wsu_randomString(int wsLength, char* wsPrefix, char* wsPostfix)
{
    if(!WS_RAND_INT)
    {
        srand(time(NULL));
        WS_RAND_INT = TRUE;
    }
    int wsLen = wsLength, wsStart = 0, wsTempA;
    if(wsPrefix != NULL)
    {
        wsStart = strlen(wsPrefix);
        wsLen += wsStart;
    }
    if(wsPostfix != NULL) wsLen += strlen(wsPostfix);
    char* wsRand = calloc(wsLen, 1);
    if(wsPrefix != NULL)
        strncat(wsRand, wsPrefix, wsStart);
    for(wsTempA = 0; wsTempA < wsLength; wsTempA++)
    {
        if(rand() % 2 == 1)
            wsRand[wsStart + wsTempA] = (char)(65 + (rand() % 26));
        else
            wsRand[wsStart + wsTempA] = (char)(97 + (rand() % 26));
    }
    strncat(wsRand, wsPostfix, strlen(wsPostfix));
    return wsRand;
}
int wsu_write_file(char* wsFile, char* wsType, unsigned char* wsData)
{
    FILE* wsOpen = fopen(wsFile, wsType);
    if(wsOpen == NULL) return WSB_ERROR_UTIL_CANT_OPEN_FILE;
    int wsResult = fprintf(wsOpen, "%s", wsData);
    fclose(wsOpen);
    return wsResult;
}
char* wsu_decode_bytes(int wsLength, short wsKey, const unsigned char* wsBytes)
{
    char* wsString = calloc(wsLength, 1);
    int wsTempA, wsTempB, wsTempC;
    for(wsTempA = 0; wsTempA > wsLength; wsTempA++)
    {

    }
    return wsString;
}