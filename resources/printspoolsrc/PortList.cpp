// PortList.cpp
//
//////////////////////////////////////////////////////////////////////

#include "PortList.h"

//////////////////////////////////////////////////////////////////////
// Konstruktion/Destruktion
//////////////////////////////////////////////////////////////////////

CPortList::CPortList(TCHAR *sMonitorName,TCHAR *sPortDesc)
{
	if(sMonitorName)
		m_sMonitorName=_tcsdup(sMonitorName);
	else
		m_sMonitorName=_tcsdup(_T(""));

	if(sPortDesc)
		m_sPortDesc=_tcsdup(sPortDesc);
	else
		m_sPortDesc=_tcsdup(_T(""));
	
	// Lege Pseudo-Knoten an
	m_pFirst=new PORT;
	
	m_pFirst->pNext=NULL;
	m_pFirst->dwStatus=0;
	m_pFirst->hFile=0;
	m_pFirst->dwJobID=0;

	_tcscpy(m_pFirst->sPath,_T(""));
	_tcscpy(m_pFirst->sCurDocument,_T(""));
	_tcscpy(m_pFirst->sPrinter,_T(""));
}

CPortList::~CPortList()
{
	free(m_sMonitorName);
	free(m_sPortDesc);

	// Loesche alle Knoten
	PORT *pNext;
	while(m_pFirst)
	{
		pNext=m_pFirst->pNext;
		delete m_pFirst;
		m_pFirst=pNext;
	}
}

//////////////////////////////////////////////////////////////////////
// Konstruktion/Destruktion
//////////////////////////////////////////////////////////////////////

BOOL CPortList::EnumPorts(
	LPWSTR   pName,
	DWORD   Level,
	LPBYTE  pPorts,
	DWORD   cbBuf,
	LPDWORD pcbNeeded,
	LPDWORD pcReturned)
{
    LPBYTE  pEnd;
    DWORD   LastError=0;

	//EnterSplSem();

    DWORD cb=0;

	PORT *pPort=m_pFirst;
    while (pPort->pNext)
	{
        cb+=GetPortSize(pPort->sPath, Level);
        pPort=pPort->pNext;
    }

    *pcbNeeded=cb;

    if (cb <= cbBuf)
	{
        //Buffer ist gross genug
		pEnd=pPorts+cbBuf;
        *pcReturned=0;

        pPort=m_pFirst;
        while (pPort->pNext)
		{
            pEnd = CopyPortToBuffer(pPort, Level, pPorts, pEnd);

            switch (Level)
			{
            case 1:
                pPorts+=sizeof(PORT_INFO_1);
                break;
            case 2:
                pPorts+=sizeof(PORT_INFO_2);
                break;
            default:
                LastError = ERROR_INVALID_LEVEL;
                goto Cleanup;
            }//switch
            (*pcReturned)++;

            pPort=pPort->pNext;
        }//while pPort->pNext

    }
	else
	{
		//Buffer nicht gross genug
        LastError = ERROR_INSUFFICIENT_BUFFER;
	}

Cleanup:
//   LeaveSplSem();

    if (LastError)
	{
        SetLastError(LastError);
        return FALSE;
    }
	else
	{
		return TRUE;
	}
}

DWORD CPortList::GetPortSize(
	TCHAR *pName,
	DWORD dwLevel)
{
    DWORD   cb;
    
    switch (dwLevel) {

    case 1:

        cb=sizeof(PORT_INFO_1) +
			_tcslen(pName)*sizeof(TCHAR) + 
			sizeof(TCHAR);
        break;

    case 2:
        cb = _tcslen(pName) + 1 +
             _tcslen(m_sMonitorName) + 1 +
             _tcslen(m_sPortDesc) + 1;
        cb *= sizeof(TCHAR);
        cb += sizeof(PORT_INFO_2);
        break;

    default:
        cb = 0;
        break;
    }

    return cb;
}

LPBYTE CPortList::CopyPortToBuffer(
	PORT *pPort,
	DWORD dwLevel,
	LPBYTE pStart,
	LPBYTE pEnd)
{
	switch(dwLevel)
	{
	case 1:
		{
			PORT_INFO_1 *pPortInfo=(PORT_INFO_1*)pStart;
			pEnd-=_tcslen(pPort->sPath) * sizeof(TCHAR) + sizeof(TCHAR);
			pPortInfo->pName=_tcscpy((TCHAR*)pEnd,pPort->sPath);
			
			break;
		}
	case 2:
		{
			PORT_INFO_2 *pPortInfo=(PORT_INFO_2*)pStart;
			pEnd-=_tcslen(m_sMonitorName) * sizeof(TCHAR) + sizeof(TCHAR);
			pPortInfo->pMonitorName=_tcscpy((TCHAR*)pEnd,m_sMonitorName);

			pEnd-=_tcslen(m_sPortDesc) * sizeof(TCHAR) + sizeof(TCHAR);
			pPortInfo->pDescription=_tcscpy((TCHAR*)pEnd,m_sPortDesc);

			pEnd-=_tcslen(pPort->sPath) * sizeof(TCHAR) + sizeof(TCHAR);
			pPortInfo->pPortName=_tcscpy((TCHAR*)pEnd,pPort->sPath);

			pPortInfo->fPortType=0;
			pPortInfo->Reserved=0;

			break;
		}
	default:
		MessageBox(0,_T("Error"),_T("invalid level"),MB_OK);
	}//switch

    return pEnd;
}

BOOL CPortList::AddPort(TCHAR *sPath, DWORD dwStatus)
{
	PORT *pNew=new PORT;
	
	if(!pNew)
		return FALSE;

	pNew->pNext=m_pFirst;
	pNew->dwStatus=dwStatus;
	pNew->hFile=0;
	pNew->dwJobID=0;

	_tcscpy(pNew->sPath,sPath);
	_tcscpy(pNew->sCurDocument,_T(""));
	_tcscpy(pNew->sPrinter,_T(""));

	m_pFirst=pNew;

	return TRUE;
}

void CPortList::Save(TCHAR *sRoot)
{
	HKEY hKey;

	// Registry-Key oeffnen
	if(RegOpenKeyEx(
		HKEY_LOCAL_MACHINE,
		sRoot,
		0,
		KEY_SET_VALUE | KEY_READ,
		&hKey) != ERROR_SUCCESS)
			return;

	// Alle vorhandenen Ports loeschen
	DWORD z;
	TCHAR sPort[5];

	z=1;
	do
	{
		_ultot(z++,sPort,10);
	}while(RegDeleteValue(hKey,sPort)==ERROR_SUCCESS);

	// Ports schreiben
	PORT *pPort=m_pFirst;

	z=Count();
	while(pPort->pNext)
	{
		_ultot(z--,sPort,10);

		RegSetValueEx(
			hKey,
			sPort,					//value name
			0,						//reserved
			REG_SZ,					//typ
			(BYTE*)pPort->sPath,	//value
			_tcslen(pPort->sPath)*sizeof(TCHAR));
		

		pPort=pPort->pNext;
	}

	// Registry-Key schliessen
	RegCloseKey(hKey);
}

void CPortList::Load(TCHAR *sRoot)
{
	HKEY hKey;

	// Registry-Key oeffnen
	if(RegOpenKeyEx(
		HKEY_LOCAL_MACHINE,
		sRoot,
		0,
		KEY_QUERY_VALUE,
		&hKey) != ERROR_SUCCESS)
			return;

	// Pfade der Ports lesen
	TCHAR sPath[MAX_PATH];
	TCHAR sPort[5];

	DWORD dwSize;
	LONG ret;

	DWORD z=1;

	do
	{
		_ultot(z++,sPort,10);

		dwSize=sizeof(sPath);
		ret=RegQueryValueEx(
			hKey,		
			sPort,			//value name
			0,				//reserved
			NULL,			//Typ
			(BYTE*)sPath,	//value
			&dwSize);		//buffer size

		if(ret==ERROR_SUCCESS)
			AddPort(sPath,0);
	}while(ret==ERROR_SUCCESS);

	// Registry-Key schliessen
	RegCloseKey(hKey);
}

PORT *CPortList::FindPort(TCHAR *sPath)
{
	PORT *pPort=m_pFirst;

	while(pPort->pNext)
	{
		if(_tcsicmp(sPath,pPort->sPath)==0)
			return pPort;
		pPort=pPort->pNext;
	}

	return NULL;
}

BOOL CPortList::DeletePort(TCHAR *sPath)
{
	PORT *pPort=m_pFirst;
	PORT *pPrevPort=m_pFirst;
	
	while(pPort->pNext)
	{
		if(_tcsicmp(sPath,pPort->sPath)==0)
		{
			if(pPort==m_pFirst)
			{
				m_pFirst=m_pFirst->pNext;
				delete pPort;
			}
			else
			{
				pPrevPort->pNext=pPort->pNext;
				delete pPort;
			}

			return TRUE;
		}
		
		pPrevPort=pPort;
		pPort=pPort->pNext;
	}

	return FALSE;
}

DWORD CPortList::Count()
{
	DWORD dwCount=0;
	PORT *pPort=m_pFirst;

	while(pPort->pNext)
	{
		++dwCount;
		pPort=pPort->pNext;
	}

	return dwCount;
}
