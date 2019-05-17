// PortList.h
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_PORTLIST_H__5BD71A00_2079_11D5_A737_00E07D80352D__INCLUDED_)
#define AFX_PORTLIST_H__5BD71A00_2079_11D5_A737_00E07D80352D__INCLUDED_

#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <winspool.h>
#include "winsplp.h"
#include <shlobj.h>
#include <limits.h>

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

//PortStatus values
#define PS_STARTDOC	0x001
#define PS_OPENED	0x002

typedef struct tagPort
{
	TCHAR sPath[MAX_PATH];
	TCHAR sCurDocument[MAX_PATH];
	DWORD dwStatus;
	HANDLE hFile;
	TCHAR sPrinter[MAX_PATH];
	DWORD dwJobID;
	tagPort *pNext;
} PORT, *LPPORT;

class CPortList  
{
	PORT *m_pFirst;

public:
	DWORD Count();
	CPortList(TCHAR *sMonitorName=NULL,TCHAR *sPortDesc=NULL);
	virtual ~CPortList();

	void Save(TCHAR *sRoot);
	void Load(TCHAR *sRoot);

	BOOL EnumPorts(LPWSTR pName, DWORD Level,LPBYTE pPorts, DWORD cbBuf, LPDWORD pcbNeeded, LPDWORD pcReturned);
	BOOL AddPort(TCHAR *sPath, DWORD dwStatus);
	BOOL DeletePort(TCHAR *sPath);
	PORT *FindPort(TCHAR *sPath);

private:
	TCHAR *m_sPortDesc;
	TCHAR *m_sMonitorName;
	LPBYTE CopyPortToBuffer(PORT *pPort,DWORD Level,LPBYTE pStart,LPBYTE pEnd);
	DWORD GetPortSize(TCHAR *pName,DWORD dwLevel);
};

#endif // !defined(AFX_PORTLIST_H__5BD71A00_2079_11D5_A737_00E07D80352D__INCLUDED_)
