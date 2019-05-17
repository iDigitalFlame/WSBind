// Monitor.cpp : main module; defines all functions
// which are exported from the DLL

#define MONITOR_EXPORTS

#include "PortList.h"
#include "Monitor.h"

#define szLocalMonitor	_T("Local Directory Print Monitor")
#define szPortDesc		_T("Local Directory Port")

HINSTANCE			hInst=NULL;
HINSTANCE			hSpoolssDll=NULL;

CRITICAL_SECTION	SpoolerSection;

HANDLE				m_hEvent=NULL;
CPortList			*m_portlist=NULL;
TCHAR				*m_sRegistryRoot=NULL;

typedef BOOL (WINAPI *fpENUMPORTS)
	(
	LPWSTR  pName,
	DWORD   Level,
	LPBYTE  pPorts,
	DWORD   cbBuf,
	LPDWORD pcbNeeded,
	LPDWORD pcReturned
	);

BOOL PortExists(
	TCHAR *pServerName, 
	TCHAR *pPortName, 
	DWORD *pError)
{
	BOOL			Found = TRUE;
	fpENUMPORTS		pfnSpoolssEnumPorts;
	
	DWORD			cbNeeded;
    DWORD			cReturned;
    DWORD			cbPorts;

    LPPORT_INFO_1	pPorts;

    *pError = NO_ERROR;

	// load SPOOLSS.DLL
    if (!hSpoolssDll)
        hSpoolssDll = LoadLibrary(L"SPOOLSS.DLL");

	if(!hSpoolssDll)
	{
		*pError=GetLastError();
	}
	else
	{
		// get function EnumPort
		pfnSpoolssEnumPorts = (fpENUMPORTS)GetProcAddress(hSpoolssDll,"EnumPortsW");
        if(!pfnSpoolssEnumPorts)
		{
			*pError = GetLastError();
			FreeLibrary(hSpoolssDll);
			hSpoolssDll = NULL;
		}
	}

	// got no function
    if (!pfnSpoolssEnumPorts)
        Found=TRUE;

	// execute EnumPorts, to obtain needed buffer size
    (*pfnSpoolssEnumPorts)(pServerName, 1, NULL, 0, &cbNeeded, &cReturned);

    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
	{
		Found=TRUE;
	}
	else
    {
        cbPorts = cbNeeded;
        pPorts = (LPPORT_INFO_1)new BYTE[cbPorts];

        if(!pPorts)
		{
			Found=TRUE;
		}
		else
        {
            if(!(*pfnSpoolssEnumPorts)(
				pServerName, 
				1, 
				(LPBYTE)pPorts, 
				cbPorts,
				&cbNeeded, 
				&cReturned))
			{
				Found=TRUE;
			}
			else
            {
                Found = FALSE;

                for (DWORD z = 0; z < cReturned; z++)
                {
                    if(_tcsicmp(pPorts[z].pName, pPortName)==0)
                        Found = TRUE;
                }
            }
        }//(!pPorts)

        delete pPorts;
    }//(GetLastError() != ERROR_INSUFFICIENT_BUFFER)

    return Found;
}

BOOL FileExists(TCHAR *sFilePath)
{
	WIN32_FIND_DATA w32fd;
	HANDLE hFile=FindFirstFile(sFilePath,&w32fd);
	if(hFile!=INVALID_HANDLE_VALUE)
	{
		FindClose(hFile);
		return TRUE;
	}
	
	return FALSE; 
}

BOOL APIENTRY DllMain(
	HINSTANCE hModule, 
	DWORD  dwReason, 
	LPVOID lpRes)
{
	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:

	        hInst = hModule;

	        InitializeCriticalSection(&SpoolerSection);
        	DisableThreadLibraryCalls((HINSTANCE)hModule);

			m_portlist=new CPortList();

	        return TRUE;

	case DLL_PROCESS_DETACH:
	case DLL_THREAD_DETACH:

		if(m_hEvent)
			CloseHandle(m_hEvent);

		if(m_sRegistryRoot)
			free((void*)m_sRegistryRoot);

		if(hSpoolssDll)
			FreeLibrary(hSpoolssDll);

		delete m_portlist;
	        return TRUE;
    }


    UNREFERENCED_PARAMETER( lpRes );
	return TRUE;
}

void EnterCritSection()
{
	EnterCriticalSection(&SpoolerSection);
}

void LeaveCritSection()
{
	LeaveCriticalSection(&SpoolerSection);
}


BOOL WINAPI MyEnumPorts(
	LPWSTR pName,
	DWORD dwLevel,
	LPBYTE pPorts,
	DWORD cbBuf,
	LPDWORD pdwNeeded,
	LPDWORD pdwReturned)
{
	EnterCritSection();

	BOOL bResult = m_portlist->EnumPorts(
		pName,
		dwLevel,
		pPorts,
		cbBuf,
		pdwNeeded,
		pdwReturned);

	LeaveCritSection();

	return bResult;
}


BOOL WINAPI MyOpenPort(
	LPWSTR   pName,
	PHANDLE pHandle)
{
	EnterCritSection();

	PORT *pPort=m_portlist->FindPort(pName);
	*pHandle=(HANDLE)pPort;
	pPort->dwStatus |= PS_OPENED;

	LeaveCritSection();

	return pPort!=NULL;
}

BOOL WINAPI MyStartDocPort(
	HANDLE  hPort,
	LPWSTR  pPrinterName,
	DWORD   JobId,
	DWORD   Level,
	LPBYTE  pDocInfo)
{
	EnterCritSection();

	PORT *pPort=(PORT*)hPort;

	if(pPort->dwStatus & PS_STARTDOC)
	{
		LeaveCritSection();
		return FALSE;
	}

	TCHAR filepath[MAX_PATH];

	_tcscpy(filepath,pPort->sPath);
	switch(Level)
	{
	case 1:
		{
			DOC_INFO_1 *pDoc=(DOC_INFO_1*)pDocInfo;
			_tcscat(filepath,pDoc->pDocName);
			break;
		}
	case 2:
		{
			DOC_INFO_2 *pDoc=(DOC_INFO_2*)pDocInfo;
			_tcscat(filepath,pDoc->pDocName);
			break;
		}
	}

	//filepath contains now the full path of output file
	//change file extension to .ps
	PathRenameExtension(filepath,_T(".ps"));


	//If output file exists: try to delete
	if(FileExists(filepath))
		DeleteFile(filepath);
	
	pPort->hFile=::CreateFile(
		filepath,
		GENERIC_WRITE,
		0,			//dont share the file
		NULL,			//SECURITY_ATTRIBUTES --> Handle cannot be inherited
		CREATE_NEW,	
		FILE_ATTRIBUTE_NORMAL,
		NULL);			//no template file

	if(pPort->hFile==INVALID_HANDLE_VALUE)
	{
		//could not open file
		pPort->hFile=0;

		HANDLE hPrinter;
		if(OpenPrinter(pPrinterName,&hPrinter,NULL))
		{
			SetJob(
				hPrinter,
				JobId,
				0,
				NULL,
				JOB_CONTROL_RESTART);

			SetJob(
				hPrinter,
				JobId,
				0,
				NULL,
				JOB_CONTROL_PAUSE);

			CloseHandle(hPrinter);

			LeaveCritSection();
			return FALSE;
		}
	}
	else
	{
		//file successfully opened
		_tcscpy(pPort->sCurDocument,filepath);
		_tcscpy(pPort->sPrinter,pPrinterName);
		pPort->dwStatus|=PS_STARTDOC;
		pPort->dwJobID=JobId;
	}

	LeaveCritSection();

	return TRUE;
}

BOOL WINAPI MyWritePort(
	HANDLE  hPort,
	LPBYTE  pBuffer,
	DWORD   cbBuf,
	LPDWORD pcbWritten)
{
	PORT *pPort=(PORT*)hPort;
	if(pPort->hFile)
	{
		EnterCritSection();

		BOOL bResult=WriteFile(
			pPort->hFile,
			pBuffer,
			cbBuf,
			pcbWritten,
			NULL);

		LeaveCritSection();

		if(!bResult)
		{
			HANDLE hPrinter;
			if(OpenPrinter(pPort->sPrinter,&hPrinter,NULL))
			{
				SetJob(
					hPrinter,
					pPort->dwJobID,
					0,
					NULL,
					JOB_CONTROL_RESTART);

				SetJob(
					hPrinter,
					pPort->dwJobID,
					0,
					NULL,
					JOB_CONTROL_PAUSE);

				CloseHandle(hPrinter);
			}
		}

		return TRUE;
	}
	
	// always return TRUE
	// ->returning FALSE leads to an useless error message 
	return TRUE;	
}

BOOL WINAPI MyReadPort(
	HANDLE hPort,
	LPBYTE pBuffer,
	DWORD  cbBuf,
	LPDWORD pcbRead)
{
	return TRUE;
}


BOOL WINAPI MyEndDocPort(HANDLE hPort)
{
	PORT *pPort=(PORT*)hPort;

	EnterCritSection();

	if(pPort->hFile)
	{
		
		FlushFileBuffers(pPort->hFile);
		CloseHandle(pPort->hFile);

		PulseEvent(m_hEvent);

		_tcscpy(pPort->sCurDocument,_T(""));
		pPort->dwStatus &= ~PS_STARTDOC;
		pPort->hFile=0;

		HANDLE hPrinter;
		if(OpenPrinter(pPort->sPrinter,&hPrinter,NULL))
		{
			SetJob(
				hPrinter,
				pPort->dwJobID,
				0,
				NULL,
				JOB_CONTROL_DELETE);

			CloseHandle(hPrinter);
		}
	}

	LeaveCritSection();
		
	return TRUE;
}

BOOL WINAPI MyClosePort(HANDLE hPort)
{
	EnterCritSection();
	PORT *pPort=(PORT*)hPort;
	pPort->dwStatus &= ~PS_OPENED;
	LeaveCritSection();

	return TRUE;
}

BOOL WINAPI MyAddPort(
	LPWSTR pName,
	HWND hWnd,
	LPWSTR pMonitorName)
{
	BROWSEINFO bi;

	bi.hwndOwner=hWnd;
	bi.pidlRoot=NULL;
	TCHAR buf[MAX_PATH];
	bi.pszDisplayName=buf;
	bi.lpszTitle=_T("Please select output-directory:");
	bi.ulFlags=BIF_RETURNONLYFSDIRS;
	bi.lpfn=NULL;
	bi.lParam=0;
	int iImage=0;
	bi.iImage=iImage;

	ITEMIDLIST *pidl=SHBrowseForFolder(&bi);

	if(pidl)//user did not cancel
	{
		TCHAR sPath[MAX_PATH];
		SHGetPathFromIDList(pidl,sPath);

		IMalloc *pMalloc;
		SHGetMalloc(&pMalloc);

		pMalloc->Free(pidl);
		pMalloc->Release();


		if(sPath[_tcslen(sPath)-1]!=_T('\\'))
			_tcscat(sPath,_T("\\"));

		DWORD err;
		if(PortExists(NULL,sPath,&err))
		{
			::MessageBox(hWnd,_T("The port cannot be added, because there\nis another one with the same name."),_T("Port already exists"),MB_OK);
		}
		else
		{
			EnterCritSection();
			m_portlist->AddPort(sPath,0);
			m_portlist->Save(m_sRegistryRoot);
			LeaveCritSection();
		}
	}
	
	return TRUE;
}

BOOL WINAPI MyAddPortEx(
	LPWSTR	pName,
	DWORD	Level,
	LPBYTE	pBuffer,
	LPWSTR	pMonitorName)
{
	return TRUE;
}

BOOL WINAPI MyConfigurePort(
	LPWSTR	pName,
	HWND	hWnd,
	LPWSTR	pPortName)
{
	MessageBox(hWnd,_T("This port cannot be configured.\n\nTo change the output-directory, add a new one."),szLocalMonitor,MB_OK);
	return TRUE;
}

BOOL WINAPI MyDeletePort(
	LPWSTR	pName,
	HWND	hWnd,
	LPWSTR	pPortName)
{
	EnterCritSection();

	if(m_portlist->DeletePort(pPortName))
	{
		m_portlist->Save(m_sRegistryRoot);
		LeaveCritSection();

		TCHAR buf[512];
		_stprintf(buf,_T("Port \"%s\" successfully removed."),pPortName);
		MessageBox(hWnd,buf,_T("Port removed"),MB_OK);
		return TRUE;
	}

	LeaveCritSection();

	MessageBox(hWnd,_T("An unknown error has occurred\n\nCouldn't remove the port."),_T("Error"),MB_OK);

	// always return TRUE
	// ->returning FALSE leads to an useless error message 
	return TRUE;	
}

BOOL IsFileReady(TCHAR *sPath)
{
	HANDLE hFile=CreateFile(
		sPath,
		GENERIC_READ,
		FILE_SHARE_WRITE|FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if(hFile==INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}
	else
	{
		CloseHandle(hFile);
		return TRUE;
	}
}

BOOL WINAPI WaitForOutput(char *paramPath, DWORD dwTimeout)
{
	TCHAR sPath[MAX_PATH];
	mbstowcs(sPath,paramPath,strlen(paramPath)+1);

	if(IsFileReady(sPath))
		return TRUE;

	HANDLE hEvent;
	hEvent=OpenEvent(SYNCHRONIZE,FALSE,szLocalMonitor);

	LARGE_INTEGER liCurrentTime;
	GetSystemTimeAsFileTime((FILETIME*)&liCurrentTime);

	LARGE_INTEGER liEndTime;
	liEndTime.QuadPart=liCurrentTime.QuadPart + dwTimeout;

	DWORD dwNextTimeout=dwTimeout;

	do
	{
		WaitForSingleObject(hEvent,dwNextTimeout+100);//respect time resolution
		if(IsFileReady(sPath))
		{
			CloseHandle(hEvent);
			return TRUE;
		}

		GetSystemTimeAsFileTime((FILETIME*)&liCurrentTime);
		dwNextTimeout=(unsigned long)((liEndTime.QuadPart-liCurrentTime.QuadPart)/10000);
	}while(dwNextTimeout>0 && dwNextTimeout<=dwTimeout);

	CloseHandle(hEvent);
	return IsFileReady(sPath);	
}

MONITOREX MonitorEx = {
    sizeof(MONITOR),
    {
        MyEnumPorts,
        MyOpenPort,
        NULL,				//OpenPortEx
        MyStartDocPort,
        MyWritePort,
		MyReadPort,
        MyEndDocPort,
        MyClosePort,
        MyAddPort,
        MyAddPortEx,
        MyConfigurePort,
        MyDeletePort,
        NULL,				//MyGetPrinterDataFromPort
        NULL				//MySetPortTimeOuts
    }
};

LPMONITOREX WINAPI InitializePrintMonitor(
	LPWSTR pRegistryRoot)
{
	if(m_sRegistryRoot)
		free((void*)m_sRegistryRoot);
	m_sRegistryRoot=_tcsdup(pRegistryRoot);
	

	m_hEvent=CreateEvent(NULL,FALSE,FALSE,szLocalMonitor);

	EnterCritSection();
	m_portlist->Load(m_sRegistryRoot);
	LeaveCritSection();

	return &MonitorEx;
}