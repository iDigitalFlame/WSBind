//This is all pretty much from the ReactOS project...

#pragma once

#define _WIN32_WINNT 0x0502     // Change this to the appropriate value to target other versions of Windows.
#define DPRINT(...)
#define DPRINT1(...)

#include <stdlib.h>
#include <tchar.h>
#include <string>
#include <ntifs.h>
#include <WinError.h>

typedef unsigned int DWORD;
typedef short WORD;
typedef unsigned char BYTE;
typedef DWORD BOOL;
typedef const char *LPCSTR; typedef char *LPSTR;
typedef const wchar_t *LPCWSTR; typedef wchar_t *LPWSTR;
typedef unsigned char *LPBYTE;
typedef void *LPVOID;
typedef unsigned int UINT;
#define WINAPI __stdcall

#define ROUND_DOWN(n, align) (((ULONG)n) & ~((align) - 1l))

#define ROUND_UP(n, align) ROUND_DOWN(((ULONG)n) + (align) - 1, (align))

typedef struct _SECURITY_ATTRIBUTES { DWORD nLength; LPVOID lpSecurityDescriptor; BOOL bInheritHandle; } SECURITY_ATTRIBUTES, *PSECURITY_ATTRIBUTES, *LPSECURITY_ATTRIBUTES;

#if 1
#define IMAGE_SUBSYSTEM_UNKNOWN                      0
#define IMAGE_SUBSYSTEM_NATIVE                       1
#define IMAGE_SUBSYSTEM_WINDOWS_GUI                  2
#define IMAGE_SUBSYSTEM_WINDOWS_CUI                  3


#define MAKE_CSR_API(Number, Server) (((Server) << 16) + Number)
#define CREATE_PROCESS                (0x0)
#define CREATE_THREAD                 (0x3F)
#define CSR_NATIVE     0x0000
typedef struct _PORT_MESSAGE
{
	union { struct { CSHORT DataLength; CSHORT TotalLength; } s1; ULONG Length; } u1;
	union { struct { CSHORT Type; CSHORT DataInfoOffset; } s2; ULONG ZeroInit; } u2;
	//__GNU_EXTENSION union { LPC_CLIENT_ID ClientId; double DoNotUseThisField; };
	ULONG MessageId;
	//__GNU_EXTENSION union { LPC_SIZE_T ClientViewSize; ULONG CallbackId; };
} PORT_MESSAGE, *PPORT_MESSAGE;
typedef struct { HANDLE NewProcessId; ULONG Flags; BOOL bInheritHandles; } CSRSS_CREATE_PROCESS, *PCSRSS_CREATE_PROCESS;
typedef struct { CLIENT_ID ClientId; HANDLE ThreadHandle; } CSRSS_CREATE_THREAD, *PCSRSS_CREATE_THREAD;
typedef struct _CSR_API_MESSAGE
{
	PORT_MESSAGE Header;
	PVOID CsrCaptureData;
	ULONG Type;
	NTSTATUS Status;
	union
	{
		CSRSS_CREATE_PROCESS CreateProcessRequest;
		CSRSS_CREATE_THREAD CreateThreadRequest;
	} Data;
} CSR_API_MESSAGE, *PCSR_API_MESSAGE;

#define HANDLE_DETACHED_PROCESS    ((HANDLE)-2)
#define HANDLE_CREATE_NEW_CONSOLE  ((HANDLE)-3)
#define HANDLE_CREATE_NO_WINDOW    ((HANDLE)-4)

#define PROFILE_USER			0x10000000
#define PROFILE_KERNEL			0x20000000
#define PROFILE_SERVER			0x40000000

#define RTL_USER_PROCESS_PARAMETERS_NORMALIZED              0x01
#define RTL_USER_PROCESS_PARAMETERS_PROFILE_USER            0x02
#define RTL_USER_PROCESS_PARAMETERS_PROFILE_SERVER          0x04
#define RTL_USER_PROCESS_PARAMETERS_PROFILE_KERNEL          0x08
#define RTL_USER_PROCESS_PARAMETERS_UNKNOWN                 0x10
#define RTL_USER_PROCESS_PARAMETERS_RESERVE_1MB             0x20
#define RTL_USER_PROCESS_PARAMETERS_DISABLE_HEAP_CHECKS     0x100
#define RTL_USER_PROCESS_PARAMETERS_PROCESS_OR_1            0x200
#define RTL_USER_PROCESS_PARAMETERS_PROCESS_OR_2            0x400
#define RTL_USER_PROCESS_PARAMETERS_PRIVATE_DLL_PATH        0x1000
#define RTL_USER_PROCESS_PARAMETERS_LOCAL_DLL_PATH          0x2000
#define RTL_USER_PROCESS_PARAMETERS_NX                      0x20000


#define OPEN_EXISTING	3
#define SEM_FAILCRITICALERRORS		0x0001
#define IMAGE_FILE_DLL                       0x2000
typedef struct _SYSTEM_BASIC_INFORMATION { ULONG Reserved; ULONG TimerResolution; ULONG PageSize; ULONG NumberOfPhysicalPages; ULONG LowestPhysicalPageNumber; ULONG HighestPhysicalPageNumber; ULONG AllocationGranularity; ULONG MinimumUserModeAddress; ULONG MaximumUserModeAddress; KAFFINITY ActiveProcessorsAffinityMask; CCHAR NumberOfProcessors; } SYSTEM_BASIC_INFORMATION, *PSYSTEM_BASIC_INFORMATION;
typedef enum _RTL_PATH_TYPE { RtlPathTypeUnknown, RtlPathTypeUncAbsolute, RtlPathTypeDriveAbsolute, RtlPathTypeDriveRelative, RtlPathTypeRooted, RtlPathTypeRelative, RtlPathTypeLocalDevice, RtlPathTypeRootLocalDevice, } RTL_PATH_TYPE;
typedef enum _SECTION_INFORMATION_CLASS { SectionBasicInformation, SectionImageInformation, } SECTION_INFORMATION_CLASS;
typedef enum _SYSTEM_INFORMATION_CLASS { SystemBasicInformation } SYSTEM_INFORMATION_CLASS;
typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
	WORD   e_magic;                     // Magic number
	WORD   e_cblp;                      // Bytes on last page of file
	WORD   e_cp;                        // Pages in file
	WORD   e_crlc;                      // Relocations
	WORD   e_cparhdr;                   // Size of header in paragraphs
	WORD   e_minalloc;                  // Minimum extra paragraphs needed
	WORD   e_maxalloc;                  // Maximum extra paragraphs needed
	WORD   e_ss;                        // Initial (relative) SS value
	WORD   e_sp;                        // Initial SP value
	WORD   e_csum;                      // Checksum
	WORD   e_ip;                        // Initial IP value
	WORD   e_cs;                        // Initial (relative) CS value
	WORD   e_lfarlc;                    // File address of relocation table
	WORD   e_ovno;                      // Overlay number
	WORD   e_res[4];                    // Reserved words
	WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
	WORD   e_oeminfo;                   // OEM information; e_oemid specific
	WORD   e_res2[10];                  // Reserved words
	LONG   e_lfanew;                    // File address of new exe header
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER { WORD Machine; WORD NumberOfSections; DWORD TimeDateStamp; DWORD PointerToSymbolTable; DWORD NumberOfSymbols; WORD SizeOfOptionalHeader; WORD Characteristics; } IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
typedef struct _IMAGE_DATA_DIRECTORY { DWORD VirtualAddress; DWORD Size; } IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES  16


typedef struct _IMAGE_OPTIONAL_HEADER {
	//
	// Standard fields.
	//

	WORD    Magic;
	BYTE    MajorLinkerVersion;
	BYTE    MinorLinkerVersion;
	DWORD   SizeOfCode;
	DWORD   SizeOfInitializedData;
	DWORD   SizeOfUninitializedData;
	DWORD   AddressOfEntryPoint;
	DWORD   BaseOfCode;
	DWORD   BaseOfData;

	//
	// NT additional fields.
	//

	DWORD   ImageBase;
	DWORD   SectionAlignment;
	DWORD   FileAlignment;
	WORD    MajorOperatingSystemVersion;
	WORD    MinorOperatingSystemVersion;
	WORD    MajorImageVersion;
	WORD    MinorImageVersion;
	WORD    MajorSubsystemVersion;
	WORD    MinorSubsystemVersion;
	DWORD   Win32VersionValue;
	DWORD   SizeOfImage;
	DWORD   SizeOfHeaders;
	DWORD   CheckSum;
	WORD    Subsystem;
	WORD    DllCharacteristics;
	DWORD   SizeOfStackReserve;
	DWORD   SizeOfStackCommit;
	DWORD   SizeOfHeapReserve;
	DWORD   SizeOfHeapCommit;
	DWORD   LoaderFlags;
	DWORD   NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
  WORD Magic;
  BYTE MajorLinkerVersion;
  BYTE MinorLinkerVersion;
  DWORD SizeOfCode;
  DWORD SizeOfInitializedData;
  DWORD SizeOfUninitializedData;
  DWORD AddressOfEntryPoint;
  DWORD BaseOfCode;
  ULONGLONG ImageBase;
  DWORD SectionAlignment;
  DWORD FileAlignment;
  WORD MajorOperatingSystemVersion;
  WORD MinorOperatingSystemVersion;
  WORD MajorImageVersion;
  WORD MinorImageVersion;
  WORD MajorSubsystemVersion;
  WORD MinorSubsystemVersion;
  DWORD Win32VersionValue;
  DWORD SizeOfImage;
  DWORD SizeOfHeaders;
  DWORD CheckSum;
  WORD Subsystem;
  WORD DllCharacteristics;
  ULONGLONG SizeOfStackReserve;
  ULONGLONG SizeOfStackCommit;
  ULONGLONG SizeOfHeapReserve;
  ULONGLONG SizeOfHeapCommit;
  DWORD LoaderFlags;
  DWORD NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS { DWORD Signature; IMAGE_FILE_HEADER FileHeader; IMAGE_OPTIONAL_HEADER32 OptionalHeader; } IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;
typedef struct _IMAGE_NT_HEADERS64 { DWORD Signature; IMAGE_FILE_HEADER FileHeader; IMAGE_OPTIONAL_HEADER64 OptionalHeader; } IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;
typedef IMAGE_NT_HEADERS32                  IMAGE_NT_HEADERS;
//typedef PIMAGE_NT_HEADERS32                 PIMAGE_NT_HEADERS;
typedef struct _GDI_TEB_BATCH { ULONG Offset; ULONG HDC; ULONG Buffer[310]; } GDI_TEB_BATCH,*PGDI_TEB_BATCH;
typedef struct _PEB { BOOLEAN InheritedAddressSpace; /* These four fields cannot change unless the */ BOOLEAN ReadImageFileExecOptions; BOOLEAN BeingDebugged; BOOLEAN SpareBool; HANDLE Mutant; /* INITIAL_PEB structure is also updated. */ PVOID ImageBaseAddress; struct _PEB_LDR_DATA* Ldr; struct _RTL_USER_PROCESS_PARAMETERS *ProcessParameters; PVOID SubSystemData; PVOID ProcessHeap; PVOID FastPebLock; PVOID FastPebLockRoutine; PVOID FastPebUnlockRoutine; ULONG EnvironmentUpdateCount; PVOID KernelCallbackTable; HANDLE EventLogSection; PVOID EventLog; struct PEB_FREE_BLOCK* FreeList; ULONG TlsExpansionCounter; PVOID TlsBitmap; ULONG TlsBitmapBits[2]; /* relates to TLS_MINIMUM_AVAILABLE */ PVOID ReadOnlySharedMemoryBase; PVOID ReadOnlySharedMemoryHeap; PVOID *ReadOnlyStaticServerData; PVOID AnsiCodePageData; PVOID OemCodePageData; PVOID UnicodeCaseTableData; /* Useful information for LdrpInitialize */ ULONG NumberOfProcessors; ULONG NtGlobalFlag; /* Passed up from MmCreatePeb from Session Manager registry key */ LARGE_INTEGER CriticalSectionTimeout; ULONG HeapSegmentReserve; ULONG HeapSegmentCommit; ULONG HeapDeCommitTotalFreeThreshold; ULONG HeapDeCommitFreeBlockThreshold; /* Where heap manager keeps track of all heaps created for a process. Fields initialized by MmCreatePeb.  ProcessHeaps is initialized to point to the first free byte after the PEB and MaximumNumberOfHeaps is computed from the page size used to hold the PEB, less the fixed size of this data structure. */ ULONG NumberOfHeaps; ULONG MaximumNumberOfHeaps; PVOID *ProcessHeaps; PVOID GdiSharedHandleTable; PVOID ProcessStarterHelper; PVOID GdiDCAttributeList; PVOID LoaderLock; /* Following fields filled in by MmCreatePeb from system values and/or image header. */ ULONG OSMajorVersion; ULONG OSMinorVersion; ULONG OSBuildNumber; ULONG OSPlatformId; ULONG ImageSubsystem; ULONG ImageSubsystemMajorVersion; ULONG ImageSubsystemMinorVersion; ULONG ImageProcessAffinityMask; ULONG GdiHandleBuffer[34]; } PEB, *PPEB;
typedef struct _TEB { NT_TIB NtTib; PVOID  EnvironmentPointer; CLIENT_ID ClientId; PVOID ActiveRpcHandle; PVOID ThreadLocalStoragePointer; PPEB ProcessEnvironmentBlock; ULONG LastErrorValue; ULONG CountOfOwnedCriticalSections; PVOID CsrClientThread; PVOID Win32ThreadInfo; /* PtiCurrent */ ULONG Win32ClientInfo[31]; /* User32 Client Info */ PVOID WOW32Reserved; /* used by WOW */ LCID CurrentLocale; ULONG FpSoftwareStatusRegister; PVOID SystemReserved1[54]; /* Used by FP emulator */ PVOID Spare1; /* unused */ NTSTATUS ExceptionCode; /* for RaiseUserException */ UCHAR SpareBytes1[40]; PVOID SystemReserved2[10]; /* Used by user/console for temp obja */ GDI_TEB_BATCH GdiTebBatch; /* Gdi batching */ ULONG gdiRgn; ULONG gdiPen; ULONG gdiBrush; CLIENT_ID RealClientId; HANDLE GdiCachedProcessHandle; ULONG GdiClientPID; ULONG GdiClientTID; PVOID GdiThreadLocalInfo; PVOID UserReserved[5]; /* unused */ PVOID glDispatchTable[280]; /* OpenGL */ ULONG glReserved1[26]; /* OpenGL */ PVOID glReserved2; /* OpenGL */ PVOID glSectionInfo; /* OpenGL */ PVOID glSection; /* OpenGL */ PVOID glTable; /* OpenGL */ PVOID glCurrentRC; /* OpenGL */ PVOID glContext; /* OpenGL */ ULONG LastStatusValue; UNICODE_STRING StaticUnicodeString; WCHAR StaticUnicodeBuffer[261]; PVOID DeallocationStack; PVOID TlsSlots[64]; LIST_ENTRY TlsLinks; PVOID Vdm; PVOID ReservedForNtRpc; PVOID DbgSsReserved[2]; ULONG HardErrorsAreDisabled; PVOID Instrumentation[16]; PVOID WinSockData; /* WinSock */ ULONG GdiBatchCount; ULONG Spare2; ULONG Spare3; ULONG Spare4; PVOID ReservedForOle; ULONG WaitingOnLoaderLock; } TEB;
typedef struct RTL_DRIVE_LETTER_CURDIR { USHORT Flags; USHORT Length; ULONG TimeStamp; UNICODE_STRING DosPath; } RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;
typedef struct _CURDIR { UNICODE_STRING DosPath; HANDLE Handle; } CURDIR, *PCURDIR;
typedef struct _RTL_USER_PROCESS_PARAMETERS { ULONG MaximumLength; ULONG Length; ULONG Flags; ULONG DebugFlags; HANDLE ConsoleHandle; ULONG ConsoleFlags; HANDLE StandardInput; HANDLE StandardOutput; HANDLE StandardError; CURDIR CurrentDirectory; UNICODE_STRING DllPath; UNICODE_STRING ImagePathName; UNICODE_STRING CommandLine; PWSTR Environment; ULONG StartingX; ULONG StartingY; ULONG CountX; ULONG CountY; ULONG CountCharsX; ULONG CountCharsY; ULONG FillAttribute; ULONG WindowFlags; ULONG ShowWindowFlags; UNICODE_STRING WindowTitle; UNICODE_STRING DesktopInfo; UNICODE_STRING ShellInfo; UNICODE_STRING RuntimeData; RTL_DRIVE_LETTER_CURDIR CurrentDirectories[32]; } RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;
typedef struct _SECTION_IMAGE_INFORMATION { PVOID TransferAddress; ULONG ZeroBits; ULONG_PTR MaximumStackSize; ULONG_PTR CommittedStackSize; ULONG SubSystemType; USHORT SubSystemMinorVersion; USHORT SubSystemMajorVersion; ULONG GpValue; USHORT ImageCharacteristics; USHORT DllCharacteristics; USHORT Machine; UCHAR ImageContainsCode; UCHAR Spare1; ULONG LoaderFlags; ULONG ImageFileSize; ULONG Reserved[1]; } SECTION_IMAGE_INFORMATION, *PSECTION_IMAGE_INFORMATION;
typedef struct _INITIAL_TEB { PVOID PreviousStackBase; PVOID PreviousStackLimit; PVOID StackBase; PVOID StackLimit; PVOID AllocatedStackBase; } INITIAL_TEB, *PINITIAL_TEB;
typedef struct _PROCESS_PRIORITY_CLASS { BOOLEAN Foreground; UCHAR PriorityClass; } PROCESS_PRIORITY_CLASS, *PPROCESS_PRIORITY_CLASS;
typedef struct _PROCESS_INFORMATION { HANDLE hProcess; HANDLE hThread; DWORD dwProcessId; DWORD dwThreadId; } PROCESS_INFORMATION, *PPROCESS_INFORMATION, *LPPROCESS_INFORMATION;
typedef struct _STARTUPINFOA{ DWORD cb; LPSTR lpReserved; LPSTR lpDesktop; LPSTR lpTitle; DWORD dwX; DWORD dwY; DWORD dwXSize; DWORD dwYSize; DWORD dwXCountChars; DWORD dwYCountChars; DWORD dwFillAttribute; DWORD dwFlags; WORD wShowWindow; WORD cbReserved2; LPBYTE lpReserved2; HANDLE hStdInput; HANDLE hStdOutput; HANDLE hStdError; } STARTUPINFOA, *LPSTARTUPINFOA;
typedef struct _STARTUPINFOW { DWORD cb; LPWSTR lpReserved; LPWSTR lpDesktop; LPWSTR lpTitle; DWORD dwX; DWORD dwY; DWORD dwXSize; DWORD dwYSize; DWORD dwXCountChars; DWORD dwYCountChars; DWORD dwFillAttribute; DWORD dwFlags; WORD wShowWindow; WORD cbReserved2; LPBYTE lpReserved2; HANDLE hStdInput; HANDLE hStdOutput; HANDLE hStdError; } STARTUPINFOW, *LPSTARTUPINFOW;
extern "C"
{
	HANDLE hBaseDir = NULL;

	BOOL WINAPI CloseHandle(HANDLE hObject);
	void WINAPI SetLastError(DWORD);
	DWORD WINAPI GetFileAttributesW(LPCWSTR lpFileName);
	DWORD WINAPI GetLastError();
	HANDLE WINAPI GetProcessHeap(VOID);
	HANDLE WINAPI CreateFileW (LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
	DWORD WINAPI GetFullPathNameW(LPCWSTR lpFileName, DWORD nBufferLength, LPWSTR lpBuffer, LPWSTR *lpFilePart);
	DWORD WINAPI SearchPathW(LPCWSTR lpPath, LPCWSTR lpFileName, LPCWSTR lpExtension, DWORD nBufferLength, LPWSTR lpBuffer, LPWSTR *lpFilePart);
	NTSYSAPI struct _TEB *NtCurrentTeb();
	NTSYSAPI NTSTATUS NTAPI NtIsProcessInJob(IN HANDLE ProcessHandle, IN HANDLE JobHandle OPTIONAL);
	NTSYSCALLAPI NTSTATUS NTAPI NtSetInformationProcess(IN HANDLE ProcessHandle, IN PROCESSINFOCLASS ProcessInformationClass, IN PVOID ProcessInformation, IN ULONG ProcessInformationLength);
	NTSYSCALLAPI NTSTATUS NTAPI NtDuplicateObject(IN HANDLE SourceProcessHandle, IN HANDLE SourceHandle, IN HANDLE TargetProcessHandle, OUT PHANDLE TargetHandle, IN ACCESS_MASK DesiredAccess, IN ULONG HandleAttributes, IN ULONG Options);
	NTSYSCALLAPI NTSTATUS NTAPI NtCreateProcess(OUT PHANDLE ProcessHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL, IN HANDLE ParentProcess, IN BOOLEAN InheritObjectTable, IN HANDLE SectionHandle OPTIONAL, IN HANDLE DebugPort OPTIONAL, IN HANDLE ExceptionPort OPTIONAL);
	NTSYSCALLAPI NTSTATUS NTAPI NtResumeThread(IN HANDLE ThreadHandle, OUT PULONG SuspendCount);
	NTSYSCALLAPI NTSTATUS NTAPI NtReadVirtualMemory(IN HANDLE ProcessHandle, IN PVOID BaseAddress, OUT PVOID Buffer, IN SIZE_T NumberOfBytesToRead, OUT PSIZE_T NumberOfBytesRead);
	NTSYSCALLAPI NTSTATUS NTAPI NtTerminateProcess(IN HANDLE ProcessHandle, IN NTSTATUS ExitStatus);
	NTSYSCALLAPI NTSTATUS NTAPI NtWriteVirtualMemory(IN HANDLE ProcessHandle, IN PVOID  BaseAddress, IN PVOID Buffer, IN SIZE_T NumberOfBytesToWrite, OUT PSIZE_T NumberOfBytesWritten);
	NTSYSCALLAPI NTSTATUS NTAPI NtQuerySection(IN HANDLE SectionHandle, IN SECTION_INFORMATION_CLASS SectionInformationClass, OUT PVOID SectionInformation, IN SIZE_T Length, OUT PSIZE_T ResultLength);
	NTSYSAPI ULONG NTAPI RtlDetermineDosPathNameType_U(IN PCWSTR Path);
	NTSYSAPI BOOLEAN NTAPI RtlDosPathNameToNtPathName_U(IN PCWSTR DosPathName, OUT PUNICODE_STRING NtPathName, OUT PCWSTR *NtFileNamePart, OUT CURDIR *DirectoryInfo);
	NTSYSAPI VOID NTAPI RtlDestroyEnvironment(IN PWSTR Environment);
	NTSYSAPI NTSTATUS NTAPI RtlCreateProcessParameters(OUT PRTL_USER_PROCESS_PARAMETERS *ProcessParameters, IN PUNICODE_STRING ImagePathName OPTIONAL, IN PUNICODE_STRING DllPath OPTIONAL, IN PUNICODE_STRING CurrentDirectory OPTIONAL, IN PUNICODE_STRING CommandLine OPTIONAL, IN PWSTR Environment OPTIONAL, IN PUNICODE_STRING WindowTitle OPTIONAL, IN PUNICODE_STRING DesktopInfo OPTIONAL, IN PUNICODE_STRING ShellInfo OPTIONAL, IN PUNICODE_STRING RuntimeInfo OPTIONAL);
	NTSYSAPI NTSTATUS NTAPI RtlDestroyProcessParameters(IN PRTL_USER_PROCESS_PARAMETERS ProcessParameters);
	NTSTATUS NTAPI CsrClientCallServer(struct _CSR_API_MESSAGE *Request, struct _CSR_CAPTURE_BUFFER *CaptureBuffer OPTIONAL, ULONG ApiNumber, ULONG RequestLength);
	NTSYSCALLAPI NTSTATUS NTAPI NtCreateThread(OUT PHANDLE ThreadHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL, IN HANDLE ProcessHandle, OUT PCLIENT_ID ClientId, IN PCONTEXT ThreadContext, IN PINITIAL_TEB UserStack, IN BOOLEAN CreateSuspended );
	NTSTATUS NTAPI NtQuerySystemInformation(IN SYSTEM_INFORMATION_CLASS SystemInformationClass, OUT PVOID SystemInformation, IN ULONG Length, OUT PULONG UnsafeResultLength);
	PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(IN PVOID BaseAddress);
	NTSYSCALLAPI NTSTATUS NTAPI NtProtectVirtualMemory(IN HANDLE ProcessHandle, IN PVOID *BaseAddress, IN SIZE_T *NumberOfBytesToProtect, IN ULONG NewAccessProtection, OUT PULONG OldAccessProtection);
	BOOL WINAPI QueryPerformanceFrequency(PLARGE_INTEGER);
	BOOL __stdcall CreateProcessW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, PWSTR lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
}
LPWSTR WINAPI BasepGetDllPath(LPWSTR FullPath, PVOID Environment) { (void)FullPath; (void)Environment; /* FIXME: Not yet implemented */ return NULL; }
#define SetLastErrorByStatus(__S__) ((void)SetLastError(RtlNtStatusToDosError(__S__)))
#define RtlGetProcessHeap() GetProcessHeap()
#define CMD_STRING L"cmd /c "
#define NtCurrentPeb() (NtCurrentTeb()->ProcessEnvironmentBlock)
#define MAX_PATH 260
#define INVALID_FILE_ATTRIBUTES 0xFFFFFFFF
#define INVALID_HANDLE_VALUE ((HANDLE)0xFFFFFFFFFFFFFFFF)
#define NORMAL_PRIORITY_CLASS		0x00000020
#define IDLE_PRIORITY_CLASS		0x00000040
#define HIGH_PRIORITY_CLASS		0x00000080
#define REALTIME_PRIORITY_CLASS		0x00000100

#define STARTF_USESHOWWINDOW 1
#define STARTF_USESIZE 2
#define STARTF_USEPOSITION 4
#define STARTF_USECOUNTCHARS 8
#define STARTF_USEFILLATTRIBUTE 16
#define STARTF_RUNFULLSCREEN 32
#define STARTF_FORCEONFEEDBACK 64
#define STARTF_FORCEOFFFEEDBACK 128
#define STARTF_USESTDHANDLES 256
#define STARTF_USEHOTKEY 512
#define STARTF_SHELLPRIVATE         0x400

#define RPL_MASK                0x0003
#define MODE_MASK               0x0001
#define KGDT_R0_CODE            0x8
#define KGDT_R0_DATA            0x10
#define KGDT_R3_CODE            0x18
#define KGDT_R3_DATA            0x20
#define KGDT_TSS                0x28
#define KGDT_R0_PCR             0x30
#define KGDT_R3_TEB             0x38
#define KGDT_LDT                0x48
#define KGDT_DF_TSS             0x50
#define KGDT_NMI_TSS            0x58
#define KGDT64_NULL             0x0000
#define KGDT64_R0_CODE          0x0010
#define KGDT64_R0_DATA          0x0018
#define KGDT64_R3_CMCODE        0x0020
#define KGDT64_R3_DATA          0x0028
#define KGDT64_R3_CODE          0x0030
#define KGDT64_SYS_TSS          0x0040
#define KGDT64_R3_CMTEB         0x0050

#define DEBUG_PROCESS			0x00000001
#define DEBUG_ONLY_THIS_PROCESS		0x00000002
#define CREATE_SUSPENDED		0x00000004
#define DETACHED_PROCESS		0x00000008
#define CREATE_NEW_CONSOLE		0x00000010
#define NORMAL_PRIORITY_CLASS		0x00000020
#define IDLE_PRIORITY_CLASS		0x00000040
#define HIGH_PRIORITY_CLASS		0x00000080
#define REALTIME_PRIORITY_CLASS		0x00000100
#define CREATE_NEW_PROCESS_GROUP	0x00000200
#define CREATE_UNICODE_ENVIRONMENT	0x00000400
#define CREATE_SEPARATE_WOW_VDM		0x00000800
#define CREATE_SHARED_WOW_VDM		0x00001000
#define CREATE_FORCEDOS			0x00002000
#define BELOW_NORMAL_PRIORITY_CLASS	0x00004000
#define ABOVE_NORMAL_PRIORITY_CLASS	0x00008000
#define CREATE_BREAKAWAY_FROM_JOB	0x01000000
#define CREATE_PRESERVE_CODE_AUTHZ_LEVEL 0x02000000
#define CREATE_DEFAULT_ERROR_MODE	0x04000000
#define CREATE_NO_WINDOW		0x08000000

#define SEC_IMAGE                                           0x1000000

#define PROCESS_PRIORITY_CLASS_INVALID          0
#define PROCESS_PRIORITY_CLASS_IDLE             1
#define PROCESS_PRIORITY_CLASS_NORMAL           2
#define PROCESS_PRIORITY_CLASS_HIGH             3
#define PROCESS_PRIORITY_CLASS_REALTIME         4
#define PROCESS_PRIORITY_CLASS_BELOW_NORMAL     5
#define PROCESS_PRIORITY_CLASS_ABOVE_NORMAL     6
#define IsConsoleHandle(h) (((((ULONG_PTR)h) & 0x10000003) == 0x3) ? TRUE : FALSE)
#ifdef UNICODE
typedef STARTUPINFOW STARTUPINFO;
typedef LPSTARTUPINFOW LPSTARTUPINFO;
#else
typedef STARTUPINFOA STARTUPINFO;
typedef LPSTARTUPINFOA LPSTARTUPINFO;
#endif // UNICODE

NTSTATUS
WINAPI
BasepNotifyCsrOfThread(IN HANDLE ThreadHandle,
		       IN PCLIENT_ID ClientId)
{
	ULONG Request = CREATE_THREAD;
	CSR_API_MESSAGE CsrRequest;
	NTSTATUS Status;

	DPRINT("BasepNotifyCsrOfThread: Thread: %lx, Handle %lx\n",
		ClientId->UniqueThread, ThreadHandle);

	/* Fill out the request */
	CsrRequest.Data.CreateThreadRequest.ClientId = *ClientId;
	CsrRequest.Data.CreateThreadRequest.ThreadHandle = ThreadHandle;

	/* Call CSR */
	Status = CsrClientCallServer(&CsrRequest,
		NULL,
		MAKE_CSR_API(Request, CSR_NATIVE),
		sizeof(CSR_API_MESSAGE));
	if (!NT_SUCCESS(Status) || !NT_SUCCESS(CsrRequest.Status))
	{
		DPRINT1("Failed to tell csrss about new thread\n");
		return CsrRequest.Status;
	}

	/* Return Success */
	return STATUS_SUCCESS;
}

VOID WINAPI BasepCopyHandles(IN PRTL_USER_PROCESS_PARAMETERS Params, IN PRTL_USER_PROCESS_PARAMETERS PebParams, IN BOOL InheritHandles)
{
	DPRINT("BasepCopyHandles %p %p, %d\n", Params, PebParams, InheritHandles);

	/* Copy the handle if we are inheriting or if it's a console handle */
	if (InheritHandles || IsConsoleHandle(PebParams->StandardInput)) { Params->StandardInput = PebParams->StandardInput; }
	if (InheritHandles || IsConsoleHandle(PebParams->StandardOutput)) { Params->StandardOutput = PebParams->StandardOutput; }
	if (InheritHandles || IsConsoleHandle(PebParams->StandardError)) { Params->StandardError = PebParams->StandardError; }
}

POBJECT_ATTRIBUTES WINAPI BasepConvertObjectAttributes(OUT POBJECT_ATTRIBUTES ObjectAttributes, IN LPSECURITY_ATTRIBUTES SecurityAttributes OPTIONAL, IN PUNICODE_STRING ObjectName)
{
	ULONG Attributes = 0;
	HANDLE RootDirectory = 0;
	PVOID SecurityDescriptor = NULL;
	BOOLEAN NeedOba = FALSE;

	DPRINT("BasepConvertObjectAttributes. Security: %p, Name: %p\n", SecurityAttributes, ObjectName);

	/* Get the attributes if present */
	if (SecurityAttributes)
	{
		Attributes = SecurityAttributes->bInheritHandle ? OBJ_INHERIT : 0;
		SecurityDescriptor = SecurityAttributes->lpSecurityDescriptor;
		NeedOba = TRUE;
	}

	if (ObjectName)
	{
		Attributes |= OBJ_OPENIF;
		RootDirectory = hBaseDir;
		NeedOba = TRUE;
	}

	DPRINT("Attributes: %lx, RootDirectory: %lx, SecurityDescriptor: %p\n",
		Attributes, RootDirectory, SecurityDescriptor);

	/* Create the Object Attributes */
	if (NeedOba)
	{
		InitializeObjectAttributes(ObjectAttributes, ObjectName, Attributes, RootDirectory,       SecurityDescriptor);
		return ObjectAttributes;
	}

	/* Nothing to return */
	return NULL;    
}

NTSTATUS
WINAPI
BasepCreateStack(HANDLE hProcess,
		 SIZE_T StackReserve,
		 SIZE_T StackCommit,
		 PINITIAL_TEB InitialTeb)
{
	NTSTATUS Status;
	SYSTEM_BASIC_INFORMATION SystemBasicInfo;
	PIMAGE_NT_HEADERS Headers;
	ULONG_PTR Stack = 0;
	BOOLEAN UseGuard = FALSE;

	DPRINT("BasepCreateStack (hProcess: %lx, Max: %lx, Current: %lx)\n",
		hProcess, StackReserve, StackCommit);

	/* Get some memory information */
	Status = NtQuerySystemInformation(SystemBasicInformation,
		&SystemBasicInfo,
		sizeof(SYSTEM_BASIC_INFORMATION),
		NULL);
	if (!NT_SUCCESS(Status))
	{
		DPRINT1("Failure to query system info\n");
		return Status;
	}

	/* Use the Image Settings if we are dealing with the current Process */
	if (hProcess == NtCurrentProcess())
	{
		/* Get the Image Headers */
		Headers = RtlImageNtHeader(NtCurrentPeb()->ImageBaseAddress);

		/* If we didn't get the parameters, find them ourselves */
		StackReserve = (StackReserve) ? StackReserve : Headers->OptionalHeader.SizeOfStackReserve;
		StackCommit = (StackCommit) ? StackCommit : Headers->OptionalHeader.SizeOfStackCommit;
	}
	else
	{
		/* Use the System Settings if needed */
		StackReserve = (StackReserve) ? StackReserve :
			SystemBasicInfo.AllocationGranularity;
	StackCommit = (StackCommit) ? StackCommit : SystemBasicInfo.PageSize;
	}

	/* Align everything to Page Size */
	StackReserve = ROUND_UP(StackReserve, SystemBasicInfo.AllocationGranularity);
	StackCommit = ROUND_UP(StackCommit, SystemBasicInfo.PageSize);
#if 1 // FIXME: Remove once Guard Page support is here
	StackCommit = StackReserve;
#endif
	DPRINT("StackReserve: %lx, StackCommit: %lx\n", StackReserve, StackCommit);

	/* Reserve memory for the stack */
	Status = NtAllocateVirtualMemory(hProcess,
		(PVOID*)&Stack,
		0,
		&StackReserve,
		MEM_RESERVE,
		PAGE_READWRITE);
	if (!NT_SUCCESS(Status))
	{
		DPRINT1("Failure to reserve stack\n");
		return Status;
	}

	/* Now set up some basic Initial TEB Parameters */
	InitialTeb->AllocatedStackBase = (PVOID)Stack;
	InitialTeb->StackBase = (PVOID)(Stack + StackReserve);
	InitialTeb->PreviousStackBase = NULL;
	InitialTeb->PreviousStackLimit = NULL;

	/* Update the Stack Position */
	Stack += StackReserve - StackCommit;

	/* Check if we will need a guard page */
	if (StackReserve > StackCommit)
	{
		Stack -= SystemBasicInfo.PageSize;
		StackCommit += SystemBasicInfo.PageSize;
		UseGuard = TRUE;
	}

	/* Allocate memory for the stack */
	Status = NtAllocateVirtualMemory(hProcess,
		(PVOID*)&Stack,
		0,
		&StackCommit,
		MEM_COMMIT,
		PAGE_READWRITE);
	if (!NT_SUCCESS(Status))
	{
		DPRINT1("Failure to allocate stack\n");
		return Status;
	}

	/* Now set the current Stack Limit */
	InitialTeb->StackLimit = (PVOID)Stack;

	/* Create a guard page */
	if (UseGuard)
	{
		SIZE_T GuardPageSize = SystemBasicInfo.PageSize;
		ULONG Dummy;

		/* Attempt maximum space possible */        
		Status = NtProtectVirtualMemory(hProcess,
			(PVOID*)&Stack,
			&GuardPageSize,
			PAGE_GUARD | PAGE_READWRITE,
			&Dummy);
		if (!NT_SUCCESS(Status))
		{
			DPRINT1("Failure to create guard page\n");
			return Status;
		}

		/* Update the Stack Limit keeping in mind the Guard Page */
		InitialTeb->StackLimit = (PVOID)((ULONG_PTR)InitialTeb->StackLimit - GuardPageSize);
	}

	/* We are done! */
	return STATUS_SUCCESS;
}


VOID
WINAPI
BasepInitializeContext(IN PCONTEXT Context,
		       IN PVOID Parameter,
		       IN PVOID StartAddress,
		       IN PVOID StackAddress,
		       IN ULONG ContextType)
{
#ifdef _M_IX86
	DPRINT("BasepInitializeContext: %p\n", Context);

	/* Setup the Initial Win32 Thread Context */
	Context->Eax = (ULONG)StartAddress;
	Context->Ebx = (ULONG)Parameter;
	Context->Esp = (ULONG)StackAddress;
	/* The other registers are undefined */

	/* Setup the Segments */
	Context->SegFs = KGDT_R3_TEB | RPL_MASK;
	Context->SegEs = KGDT_R3_DATA | RPL_MASK;
	Context->SegDs = KGDT_R3_DATA | RPL_MASK;
	Context->SegCs = KGDT_R3_CODE | RPL_MASK;
	Context->SegSs = KGDT_R3_DATA | RPL_MASK;
	Context->SegGs = 0;

	/* Set the EFLAGS */
	Context->EFlags = 0x3000; /* IOPL 3 */

	if (ContextType == 1)      /* For Threads */
	{
		__debugbreak();
		Context->Eip = (ULONG)BaseThreadStartupThunk;
	}
	else if (ContextType == 2) /* For Fibers */
	{
		__debugbreak();
		//Context->Eip = (ULONG)BaseFiberStartup;
	}
	else                       /* For first thread in a Process */
	{
		__debugbreak();
		//Context->Eip = (ULONG)BaseProcessStartThunk;
	}

	/* Set the Context Flags */
	Context->ContextFlags = CONTEXT_FULL;

	/* Give it some room for the Parameter */
	Context->Esp -= sizeof(PVOID);
#elif defined(_M_AMD64)
	DPRINT("BasepInitializeContext: %p\n", Context);

	/* Setup the Initial Win32 Thread Context */
	Context->Rax = (ULONG_PTR)StartAddress;
	Context->Rbx = (ULONG_PTR)Parameter;
	Context->Rsp = (ULONG_PTR)StackAddress;
	/* The other registers are undefined */

	/* Setup the Segments */
	Context->SegGs = KGDT64_R3_DATA | RPL_MASK;
	Context->SegEs = KGDT64_R3_DATA | RPL_MASK;
	Context->SegDs = KGDT64_R3_DATA | RPL_MASK;
	Context->SegCs = KGDT64_R3_CODE | RPL_MASK;
	Context->SegSs = KGDT64_R3_DATA | RPL_MASK;
	Context->SegFs = KGDT64_R3_CMTEB | RPL_MASK;

	/* Set the EFLAGS */
	Context->EFlags = 0x3000; /* IOPL 3 */

	if (ContextType == 1)      /* For Threads */
	{
		//__debugbreak();
		//Context->Rip = (ULONG_PTR)BaseThreadStartupThunk;
	}
	else if (ContextType == 2) /* For Fibers */
	{
		__debugbreak();
		//Context->Rip = (ULONG_PTR)BaseFiberStartup;
	}
	else                       /* For first thread in a Process */
	{
		//__debugbreak();
		Context->Rip = (ULONG_PTR)((ULONG_PTR)QueryPerformanceFrequency + 12); //BaseThreadStartupThunk
		//Context->Rip = (ULONG_PTR)BaseProcessStartThunk;
	}

	/* Set the Context Flags */
	Context->ContextFlags = CONTEXT_FULL;

	/* Give it some room for the Parameter */
	Context->Rsp -= sizeof(PVOID);
#else
#warning Unknown architecture
	UNIMPLEMENTED;
	DbgBreakPoint();
#endif
}

HANDLE
WINAPI
BasepCreateFirstThread(HANDLE ProcessHandle,
		       LPSECURITY_ATTRIBUTES lpThreadAttributes,
		       PSECTION_IMAGE_INFORMATION SectionImageInfo,
		       PCLIENT_ID ClientId)
{
	OBJECT_ATTRIBUTES LocalObjectAttributes;
	POBJECT_ATTRIBUTES ObjectAttributes;
	CONTEXT Context;
	INITIAL_TEB InitialTeb;
	NTSTATUS Status;
	HANDLE hThread;

	DPRINT("BasepCreateFirstThread. hProcess: %lx\n", ProcessHandle);

	/* Create the Thread's Stack */
	BasepCreateStack(ProcessHandle,
		SectionImageInfo->MaximumStackSize,
		SectionImageInfo->CommittedStackSize,
		&InitialTeb);

	/* Create the Thread's Context */
	BasepInitializeContext(&Context,
		NtCurrentPeb(),
		SectionImageInfo->TransferAddress,
		InitialTeb.StackBase,
		0);

	/* Convert the thread attributes */
	ObjectAttributes = BasepConvertObjectAttributes(&LocalObjectAttributes,
		lpThreadAttributes,
		NULL);

	/* Create the Kernel Thread Object */
	Status = NtCreateThread(&hThread,
		THREAD_ALL_ACCESS,
		ObjectAttributes,
		ProcessHandle,
		ClientId,
		&Context,
		&InitialTeb,
		TRUE);
	if (!NT_SUCCESS(Status))
	{
		return NULL;
	}

	Status = BasepNotifyCsrOfThread(hThread, ClientId);
	if (!NT_SUCCESS(Status))
	{
		ASSERT(FALSE);
	}

	/* Success */
	return hThread;
}

NTSTATUS
WINAPI
BasepNotifyCsrOfCreation(ULONG dwCreationFlags,
			 IN HANDLE ProcessId,
			 IN BOOL InheritHandles)
{
	ULONG Request = CREATE_PROCESS;
	CSR_API_MESSAGE CsrRequest;
	NTSTATUS Status;

	DPRINT("BasepNotifyCsrOfCreation: Process: %lx, Flags %lx\n",
		ProcessId, dwCreationFlags);

	/* Fill out the request */
	CsrRequest.Data.CreateProcessRequest.NewProcessId = ProcessId;
	CsrRequest.Data.CreateProcessRequest.Flags = dwCreationFlags;
	CsrRequest.Data.CreateProcessRequest.bInheritHandles = InheritHandles;

	/* Call CSR */
	Status = CsrClientCallServer(&CsrRequest,
		NULL,
		MAKE_CSR_API(Request, CSR_NATIVE),
		sizeof(CSR_API_MESSAGE));
	if (!NT_SUCCESS(Status) || !NT_SUCCESS(CsrRequest.Status))
	{
		DPRINT1("Failed to tell csrss about new process\n");
		return CsrRequest.Status;
	}

	/* Return Success */
	return STATUS_SUCCESS;
}

NTSTATUS
WINAPI
BasepInitializeEnvironment(HANDLE ProcessHandle,
			   PPEB Peb,
			   LPWSTR ApplicationPathName,
			   LPWSTR lpCurrentDirectory,
			   LPWSTR lpCommandLine,
			   PWSTR lpEnvironment,
			   SIZE_T EnvSize,
			   LPSTARTUPINFOW StartupInfo,
			   DWORD CreationFlags,
			   BOOL InheritHandles)
{
	WCHAR FullPath[MAX_PATH];
	LPWSTR Remaining;
	LPWSTR DllPathString;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PRTL_USER_PROCESS_PARAMETERS RemoteParameters = NULL;
	UNICODE_STRING DllPath, ImageName, CommandLine, CurrentDirectory;
	UINT RetVal;
	NTSTATUS Status;
	PWCHAR ScanChar;
	ULONG EnviroSize;
	SIZE_T Size;
	UNICODE_STRING Desktop, Shell, Runtime, Title;
	PPEB OurPeb = NtCurrentPeb();
	PWSTR Environment = lpEnvironment;

	DPRINT("BasepInitializeEnvironment\n");

	/* Get the full path name */
	RetVal = GetFullPathNameW(ApplicationPathName,
		MAX_PATH,
		FullPath,
		&Remaining);
	DPRINT("ApplicationPathName: %S, FullPath: %S\n", ApplicationPathName,
		FullPath);

	/* Get the DLL Path */
	DllPathString = BasepGetDllPath(FullPath, Environment);

	/* Initialize Strings */
	RtlInitUnicodeString(&DllPath, DllPathString);
	RtlInitUnicodeString(&ImageName, FullPath);
	RtlInitUnicodeString(&CommandLine, lpCommandLine);
	RtlInitUnicodeString(&CurrentDirectory, lpCurrentDirectory);

	/* Initialize more Strings from the Startup Info */
	if (StartupInfo->lpDesktop)
	{
		RtlInitUnicodeString(&Desktop, StartupInfo->lpDesktop);
	}
	else
	{
		RtlInitUnicodeString(&Desktop, L"");
	}
	if (StartupInfo->lpReserved)
	{
		RtlInitUnicodeString(&Shell, StartupInfo->lpReserved);
	}
	else
	{
		RtlInitUnicodeString(&Shell, L"");
	}
	if (StartupInfo->lpTitle)
	{
		RtlInitUnicodeString(&Title, StartupInfo->lpTitle);
	}
	else
	{
		RtlInitUnicodeString(&Title, L"");
	}

	/* This one is special because the length can differ */
	Runtime.Buffer = (LPWSTR)StartupInfo->lpReserved2;
	Runtime.MaximumLength = Runtime.Length = StartupInfo->cbReserved2;

	/* Create the Parameter Block */
	DPRINT("Creating Process Parameters: %wZ %wZ %wZ %wZ %wZ %wZ %wZ\n",
		&ImageName, &DllPath, &CommandLine, &Desktop, &Title, &Shell,
		&Runtime);
	Status = RtlCreateProcessParameters(&ProcessParameters, &ImageName, &DllPath, lpCurrentDirectory ? &CurrentDirectory : NULL, &CommandLine, Environment, &Title, &Desktop, &Shell, &Runtime);

	if (!NT_SUCCESS(Status))
	{
		DPRINT1("Failed to create process parameters!\n");
		return Status;
	}

	/* Check if we got an environment. If not, use ours */
	if (Environment)
	{
		/* Save pointer and start lookup */
		Environment = ScanChar = ProcessParameters->Environment;
	}
	else
	{
		/* Save pointer and start lookup */
		Environment = ScanChar = OurPeb->ProcessParameters->Environment;
	}

	/* Find the environment size */
	if (ScanChar)
	{
		if (EnvSize && Environment == lpEnvironment)
		{
			/* its a converted ansi environment, bypass the length calculation */
			EnviroSize = EnvSize;
		}
		else
		{
			while (*ScanChar)
			{
				ScanChar += wcslen(ScanChar) + 1;
			}

			/* Calculate the size of the block */
			if (ScanChar == Environment)
			{
				EnviroSize = 2 * sizeof(WCHAR);
			}
			else
			{
				EnviroSize = (ULONG)((ULONG_PTR)ScanChar - (ULONG_PTR)Environment + sizeof(WCHAR));
			}
		}
		DPRINT("EnvironmentSize %ld\n", EnviroSize);

		/* Allocate and Initialize new Environment Block */
		Size = EnviroSize;
		ProcessParameters->Environment = NULL;
		Status = NtAllocateVirtualMemory(ProcessHandle,
			(PVOID*)&ProcessParameters->Environment,
			0,
			&Size,
			MEM_COMMIT,
			PAGE_READWRITE);
		if (!NT_SUCCESS(Status))
		{
			DPRINT1("Failed to allocate Environment Block\n");
			return(Status);
		}

		/* Write the Environment Block */
		NtWriteVirtualMemory(ProcessHandle,
			ProcessParameters->Environment,
			Environment,
			EnviroSize,
			NULL);
	}

	/* Write new parameters */
	ProcessParameters->StartingX = StartupInfo->dwX;
	ProcessParameters->StartingY = StartupInfo->dwY;
	ProcessParameters->CountX = StartupInfo->dwXSize;
	ProcessParameters->CountY = StartupInfo->dwYSize;
	ProcessParameters->CountCharsX = StartupInfo->dwXCountChars;
	ProcessParameters->CountCharsY = StartupInfo->dwYCountChars;
	ProcessParameters->FillAttribute = StartupInfo->dwFillAttribute;
	ProcessParameters->WindowFlags = StartupInfo->dwFlags;
	ProcessParameters->ShowWindowFlags = StartupInfo->wShowWindow;

	/* Write the handles only if we have to */
	if (StartupInfo->dwFlags & STARTF_USESTDHANDLES)
	{
		DPRINT("Using Standard Handles\n");
		ProcessParameters->StandardInput = StartupInfo->hStdInput;
		ProcessParameters->StandardOutput = StartupInfo->hStdOutput;
		ProcessParameters->StandardError = StartupInfo->hStdError;
	}

	/* Use Special Flags for ConDllInitialize in Kernel32 */
	if (CreationFlags & DETACHED_PROCESS)
	{
		ProcessParameters->ConsoleHandle = HANDLE_DETACHED_PROCESS;
	}
	else if (CreationFlags & CREATE_NO_WINDOW)
	{
		ProcessParameters->ConsoleHandle = HANDLE_CREATE_NO_WINDOW;
	}
	else if (CreationFlags & CREATE_NEW_CONSOLE)
	{
		ProcessParameters->ConsoleHandle = HANDLE_CREATE_NEW_CONSOLE;
	}
	else
	{
		/* Inherit our Console Handle */
		ProcessParameters->ConsoleHandle = OurPeb->ProcessParameters->ConsoleHandle;

		/* Is the shell trampling on our Handles? */
		if (!(StartupInfo->dwFlags &
			(STARTF_USESTDHANDLES | STARTF_USEHOTKEY | STARTF_SHELLPRIVATE)))
		{
			/* Use handles from PEB, if inheriting or they are console */
			DPRINT("Copying handles from parent\n");
			BasepCopyHandles(ProcessParameters, OurPeb->ProcessParameters, InheritHandles);
		}
	}

	/* Also set the Console Flag */
	if (CreationFlags & CREATE_NEW_PROCESS_GROUP)
	{
		ProcessParameters->ConsoleFlags = 1;
	}

	/* Allocate memory for the parameter block */
	Size = ProcessParameters->Length;
	Status = NtAllocateVirtualMemory(ProcessHandle,
		(PVOID*)&RemoteParameters,
		0,
		&Size,
		MEM_COMMIT,
		PAGE_READWRITE);
	if (!NT_SUCCESS(Status))
	{
		DPRINT1("Failed to allocate Parameters Block\n");
		return(Status);
	}

	/* Set the allocated size */
	ProcessParameters->MaximumLength = Size;

	/* Handle some Parameter Flags */
	ProcessParameters->ConsoleFlags = (CreationFlags & CREATE_NEW_PROCESS_GROUP);
	ProcessParameters->Flags |= (CreationFlags & PROFILE_USER) ?
RTL_USER_PROCESS_PARAMETERS_PROFILE_USER : 0;
	ProcessParameters->Flags |= (CreationFlags & PROFILE_KERNEL) ?
RTL_USER_PROCESS_PARAMETERS_PROFILE_KERNEL : 0;
	ProcessParameters->Flags |= (CreationFlags & PROFILE_SERVER) ?
RTL_USER_PROCESS_PARAMETERS_PROFILE_SERVER : 0;
	ProcessParameters->Flags |= (NtCurrentPeb()->ProcessParameters->Flags &
		RTL_USER_PROCESS_PARAMETERS_DISABLE_HEAP_CHECKS);

	/* Write the Parameter Block */
	Status = NtWriteVirtualMemory(ProcessHandle,
		RemoteParameters,
		ProcessParameters,
		ProcessParameters->Length,
		NULL);

	/* Write the PEB Pointer */
	Status = NtWriteVirtualMemory(ProcessHandle,
		&Peb->ProcessParameters,
		&RemoteParameters,
		sizeof(PVOID),
		NULL);

	/* Cleanup */
	RtlFreeHeap(RtlGetProcessHeap(), 0, DllPath.Buffer);
	RtlDestroyProcessParameters(ProcessParameters);

	DPRINT("Completed\n");
	return STATUS_SUCCESS;
}

PWSTR
WINAPI
BasepConvertUnicodeEnvironment(OUT SIZE_T* EnvSize,
			       IN PVOID lpEnvironment)
{
	PCHAR pcScan;
	ANSI_STRING AnsiEnv;
	UNICODE_STRING UnicodeEnv;
	NTSTATUS Status;

	DPRINT("BasepConvertUnicodeEnvironment\n");

	/* Scan the environment to calculate its Unicode size */
	AnsiEnv.Buffer = pcScan = (PCHAR)lpEnvironment;
	while (*pcScan)
	{
		pcScan += strlen(pcScan) + 1;
	}

	/* Create our ANSI String */
	if (pcScan == (PCHAR)lpEnvironment)
	{
		AnsiEnv.Length = 2 * sizeof(CHAR);
	}
	else
	{

		AnsiEnv.Length = (USHORT)((ULONG_PTR)pcScan - (ULONG_PTR)lpEnvironment + sizeof(CHAR));
	}
	AnsiEnv.MaximumLength = AnsiEnv.Length + 1;

	/* Allocate memory for the Unicode Environment */
	UnicodeEnv.Buffer = NULL;
	*EnvSize = AnsiEnv.MaximumLength * sizeof(WCHAR);
	Status = NtAllocateVirtualMemory(NtCurrentProcess(), (PVOID*)&UnicodeEnv.Buffer, 0, EnvSize, MEM_COMMIT, PAGE_READWRITE);
	/* Failure */
	if (!NT_SUCCESS(Status))
	{
		SetLastError(Status);
		*EnvSize = 0;
		return NULL;
	}

	/* Use the allocated size */
	UnicodeEnv.MaximumLength = (USHORT)*EnvSize;

	/* Convert */
	RtlAnsiStringToUnicodeString(&UnicodeEnv, &AnsiEnv, FALSE);
	return UnicodeEnv.Buffer;
}

VOID WINAPI BasepDuplicateAndWriteHandle(IN HANDLE ProcessHandle, IN HANDLE StandardHandle, IN PHANDLE Address)
{
	NTSTATUS Status;
	HANDLE DuplicatedHandle;
	SIZE_T Dummy;
	DPRINT("BasepDuplicateAndWriteHandle. hProcess: %lx, Handle: %lx, Address: %p\n", ProcessHandle, StandardHandle, Address);
	/* Don't touch Console Handles */
	if (IsConsoleHandle(StandardHandle)) return;

	/* Duplicate the handle */
	Status = NtDuplicateObject(NtCurrentProcess(), StandardHandle, ProcessHandle, &DuplicatedHandle, DUPLICATE_SAME_ACCESS | DUPLICATE_SAME_ATTRIBUTES, 0, 0);
	if (NT_SUCCESS(Status))
	{
		/* Write it */
		NtWriteVirtualMemory(ProcessHandle, Address, &DuplicatedHandle, sizeof(HANDLE), &Dummy);
	}
}
NTSTATUS WINAPI BasepMapFile(IN LPCWSTR lpApplicationName, OUT PHANDLE hSection, IN PUNICODE_STRING ApplicationName)
{
	CURDIR RelativeName = {};
	OBJECT_ATTRIBUTES ObjectAttributes;
	NTSTATUS Status;
	HANDLE hFile = NULL;
	IO_STATUS_BLOCK IoStatusBlock;

	DPRINT("BasepMapFile\n");

	/* Zero out the Relative Directory */
	RelativeName.Handle = NULL;

	/* Find the application name */
	if (!RtlDosPathNameToNtPathName_U(lpApplicationName, ApplicationName, NULL, NULL)) { return STATUS_OBJECT_PATH_NOT_FOUND; }

	DPRINT("ApplicationName %wZ\n", ApplicationName);
	DPRINT("RelativeName %wZ\n", &RelativeName.DosPath);

	/* Did we get a relative name? */
	if (RelativeName.DosPath.Length) { ApplicationName = &RelativeName.DosPath; }

	/* Initialize the Object Attributes */
	InitializeObjectAttributes(&ObjectAttributes, ApplicationName, OBJ_CASE_INSENSITIVE, RelativeName.Handle, NULL);

	/* Try to open the executable */
	Status = NtOpenFile(&hFile, SYNCHRONIZE | FILE_EXECUTE | FILE_READ_DATA, &ObjectAttributes, &IoStatusBlock, FILE_SHARE_DELETE | FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);
	if (!NT_SUCCESS(Status))
	{
		DPRINT1("Failed to open file\n");
		SetLastErrorByStatus(Status);
		return Status;
	}

	/* Create a section for this file */
	Status = NtCreateSection(hSection, SECTION_ALL_ACCESS, NULL, NULL, PAGE_EXECUTE, SEC_IMAGE, hFile);
	NtClose(hFile);

	/* Return status */
	DPRINT("Section: %lx for file: %lx\n", *hSection, hFile);
	return Status;
}

ULONG WINAPI BasepConvertPriorityClass(IN ULONG dwCreationFlags) { ULONG ReturnClass; if(dwCreationFlags & IDLE_PRIORITY_CLASS) { ReturnClass = PROCESS_PRIORITY_CLASS_IDLE; } else if (dwCreationFlags & BELOW_NORMAL_PRIORITY_CLASS) { ReturnClass = PROCESS_PRIORITY_CLASS_BELOW_NORMAL; } else if(dwCreationFlags & NORMAL_PRIORITY_CLASS) { ReturnClass = PROCESS_PRIORITY_CLASS_NORMAL; } else if(dwCreationFlags & ABOVE_NORMAL_PRIORITY_CLASS) { ReturnClass = PROCESS_PRIORITY_CLASS_ABOVE_NORMAL; } else if(dwCreationFlags & HIGH_PRIORITY_CLASS) { ReturnClass = PROCESS_PRIORITY_CLASS_HIGH; } else if(dwCreationFlags & REALTIME_PRIORITY_CLASS) { ReturnClass = PROCESS_PRIORITY_CLASS_REALTIME; } else { ReturnClass = PROCESS_PRIORITY_CLASS_INVALID; } return ReturnClass; }

BOOL __stdcall CreateProcessInternalW(HANDLE hToken, LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, PWSTR lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation, PHANDLE hNewToken)
{
	NTSTATUS Status = 0;
	PROCESS_PRIORITY_CLASS PriorityClass;
	BOOLEAN FoundQuotes = FALSE;
	BOOLEAN QuotesNeeded = FALSE;
	BOOLEAN CmdLineIsAppName = FALSE;
	UNICODE_STRING ApplicationName = { 0, 0, NULL };
	OBJECT_ATTRIBUTES LocalObjectAttributes;
	POBJECT_ATTRIBUTES ObjectAttributes;
	HANDLE hSection = NULL, hProcess = NULL, hThread = NULL, hDebug = NULL;
	SECTION_IMAGE_INFORMATION SectionImageInfo;
	LPWSTR CurrentDirectory = NULL;
	LPWSTR CurrentDirectoryPart;
	PROCESS_BASIC_INFORMATION ProcessBasicInfo;
	STARTUPINFOW StartupInfo;
	ULONG Dummy;
	LPWSTR BatchCommandLine;
	ULONG CmdLineLength;
	UNICODE_STRING CommandLineString;
	PWCHAR Extension;
	LPWSTR QuotedCmdLine = NULL;
	LPWSTR ScanString;
	LPWSTR NullBuffer = NULL;
	LPWSTR NameBuffer = NULL;
	WCHAR SaveChar = 0;
	ULONG RetVal;
	UINT Error = 0;
	BOOLEAN SearchDone = FALSE;
	BOOLEAN Escape = FALSE;
	CLIENT_ID ClientId;
	PPEB OurPeb = NtCurrentPeb();
	PPEB RemotePeb;
	SIZE_T EnvSize = 0;
	BOOL Ret = FALSE;

	/* FIXME should process
	* HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
	* key (see http://blogs.msdn.com/oldnewthing/archive/2005/12/19/505449.aspx)
	*/

	DPRINT("CreateProcessW: lpApplicationName: %S lpCommandLine: %S"
		" lpEnvironment: %p lpCurrentDirectory: %S dwCreationFlags: %lx\n",
		lpApplicationName, lpCommandLine, lpEnvironment, lpCurrentDirectory,
		dwCreationFlags);

	/* Flags we don't handle yet */
	if (dwCreationFlags & CREATE_SEPARATE_WOW_VDM)
	{
		DPRINT1("CREATE_SEPARATE_WOW_VDM not handled\n");
	}
	if (dwCreationFlags & CREATE_SHARED_WOW_VDM)
	{
		DPRINT1("CREATE_SHARED_WOW_VDM not handled\n");
	}
	if (dwCreationFlags & CREATE_FORCEDOS)
	{
		DPRINT1("CREATE_FORCEDOS not handled\n");
	}

	/* Fail on this flag, it's only valid with the WithLogonW function */
	if (dwCreationFlags & CREATE_PRESERVE_CODE_AUTHZ_LEVEL)
	{
		DPRINT1("Invalid flag used\n");
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	/* This combination is illegal (see MSDN) */
	if ((dwCreationFlags & (DETACHED_PROCESS | CREATE_NEW_CONSOLE)) ==
		(DETACHED_PROCESS | CREATE_NEW_CONSOLE))
	{
		DPRINT1("Invalid flag combo used\n");
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	/* Another illegal combo */
	if ((dwCreationFlags & (CREATE_SEPARATE_WOW_VDM | CREATE_SHARED_WOW_VDM)) ==
		(CREATE_SEPARATE_WOW_VDM | CREATE_SHARED_WOW_VDM))
	{
		DPRINT1("Invalid flag combo used\n");
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	if (lpCurrentDirectory)
	{
		if ((GetFileAttributesW(lpCurrentDirectory) == INVALID_FILE_ATTRIBUTES) ||
			!(GetFileAttributesW(lpCurrentDirectory) & FILE_ATTRIBUTE_DIRECTORY))
		{
			SetLastError(ERROR_DIRECTORY);
			return FALSE;
		}
	}

	/*
	* We're going to modify and mask out flags and stuff in lpStartupInfo,
	* so we'll use our own local copy for that.
	*/
	StartupInfo = *lpStartupInfo;

	/* FIXME: Use default Separate/Shared VDM Flag */

	/* If we are inside a Job, use Separate VDM so it won't escape the Job */
	if (!(dwCreationFlags & CREATE_SEPARATE_WOW_VDM))
	{
		if (NtIsProcessInJob(NtCurrentProcess(), NULL))
		{
			/* Remove the shared flag and add the separate flag. */
			dwCreationFlags = (dwCreationFlags&~ CREATE_SHARED_WOW_VDM) | CREATE_SEPARATE_WOW_VDM;
		}
	}

	/*
	* According to some sites, ShellExecuteEx uses an undocumented flag to
	* send private handle data (such as HMONITOR or HICON). See:
	* www.catch22.net/tuts/undoc01.asp. This implies that we can't use the
	* standard handles anymore since we'd be overwriting this private data
	*/
	if ((StartupInfo.dwFlags & STARTF_USESTDHANDLES) && (StartupInfo.dwFlags & (STARTF_USEHOTKEY | STARTF_SHELLPRIVATE))) { StartupInfo.dwFlags &= ~STARTF_USESTDHANDLES; }

	/* Start by zeroing out the fields */
	RtlZeroMemory(lpProcessInformation, sizeof(PROCESS_INFORMATION));

	/* Easy stuff first, convert the process priority class */
	PriorityClass.Foreground = FALSE;
	PriorityClass.PriorityClass = (UCHAR)BasepConvertPriorityClass(dwCreationFlags);

	if (lpCommandLine)
	{
		/* Serach for escape sequences */
		ScanString = lpCommandLine;
		while (NULL != (ScanString = wcschr(ScanString, L'^')))
		{
			ScanString++;
			if (*ScanString == L'\"' || *ScanString == L'^' || *ScanString == L'\"')
			{
				Escape = TRUE;
				break;
			}
		}
	}

	/* Get the application name and do all the proper formating necessary */
GetAppName:
	/* See if we have an application name (oh please let us have one!) */
	if (!lpApplicationName)
	{
		/* The fun begins */
		NameBuffer= (LPWSTR)RtlAllocateHeap(RtlGetProcessHeap(), 0, MAX_PATH * sizeof(WCHAR));
		if (NameBuffer == NULL)
		{
			SetLastError(ERROR_NOT_ENOUGH_MEMORY);
			goto Cleanup;
		}

		/* This is all we have to work with :( */
		lpApplicationName = lpCommandLine;

		/* Initialize our friends at the beginning */
		NullBuffer = (LPWSTR)lpApplicationName;
		ScanString = (LPWSTR)lpApplicationName;

		/* We will start by looking for a quote */
		if (*ScanString == L'\"')
		{
			/* That was quick */
			SearchDone = TRUE;

			/* Advance past quote */
			ScanString++;
			lpApplicationName = ScanString;

			/* Find the closing quote */
			while (*ScanString)
			{
				if (*ScanString == L'\"' && *(ScanString - 1) != L'^')
				{
					/* Found it */
					NullBuffer = ScanString;
					FoundQuotes = TRUE;
					break;
				}

				/* Keep looking */
				ScanString++;
				NullBuffer = ScanString;
			}
		}
		else
		{
			/* No quotes, so we'll be looking for white space */
WhiteScan:
			/* Reset the pointer */
			lpApplicationName = lpCommandLine;

			/* Find whitespace of Tab */
			while (*ScanString)
			{
				if (*ScanString == ' ' || *ScanString == '\t')
				{
					/* Found it */
					NullBuffer = ScanString;
					break;
				}

				/* Keep looking */
				ScanString++;
				NullBuffer = ScanString;
			}
		}

		/* Set the Null Buffer */
		SaveChar = *NullBuffer;
		*NullBuffer = UNICODE_NULL;

		/* Do a search for the file */
		DPRINT("Ready for SearchPathW: %S\n", lpApplicationName);
		RetVal = SearchPathW(NULL, lpApplicationName, L".exe", MAX_PATH, NameBuffer, NULL) * sizeof(WCHAR);

		/* Did it find something? */
		if (RetVal)
		{
			/* Get file attributes */
			ULONG Attributes = GetFileAttributesW(NameBuffer);
			if (Attributes & FILE_ATTRIBUTE_DIRECTORY)
			{
				/* Give it a length of 0 to fail, this was a directory. */
				RetVal = 0;
			}
			else
			{
				/* It's a file! */
				RetVal += sizeof(WCHAR);
			}
		}

		/* Now check if we have a file, and if the path size is OK */
		if (!RetVal || RetVal >= (MAX_PATH * sizeof(WCHAR)))
		{
			ULONG PathType;
			HANDLE hFile;

			/* We failed, try to get the Path Type */
			DPRINT("SearchPathW failed. Retval: %ld\n", RetVal);
			PathType = RtlDetermineDosPathNameType_U(lpApplicationName);

			/* If it's not relative, try to get the error */
			if (PathType != RtlPathTypeRelative)
			{
				/* This should fail, and give us a detailed LastError */
				hFile = CreateFileW(lpApplicationName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

				/* Did it actually NOT fail? */
				if (hFile != INVALID_HANDLE_VALUE)
				{
					/* Fake the error */
					CloseHandle(hFile);
					SetLastErrorByStatus(STATUS_OBJECT_NAME_NOT_FOUND);
				}
			}
			else
			{
				/* Immediately set the error */
				SetLastErrorByStatus(STATUS_OBJECT_NAME_NOT_FOUND);
			}

			/* Did we already fail once? */
			if (Error)
			{
				SetLastError(Error);
			}
			else
			{
				/* Not yet, cache it */
				Error = GetLastError();
			}

			/* Put back the command line */
			*NullBuffer = SaveChar;
			lpApplicationName = NameBuffer;

			/*
			* If the search isn't done and we still have cmdline
			* then start over. Ex: c:\ha ha ha\haha.exe
			*/
			if (*ScanString && !SearchDone)
			{
				/* Move in the buffer */
				ScanString++;
				NullBuffer = ScanString;

				/* We will have to add a quote, since there is a space*/
				QuotesNeeded = TRUE;

				/* And we will also fake the fact we found one */
				FoundQuotes = TRUE;

				/* Start over */
				goto WhiteScan;
			}

			/* We totally failed */
			goto Cleanup;
		}

		/* Put back the command line */
		*NullBuffer = SaveChar;
		lpApplicationName = NameBuffer;
		DPRINT("SearchPathW suceeded (%ld): %S\n", RetVal, NameBuffer);
	}
	else if (!lpCommandLine || *lpCommandLine == UNICODE_NULL)
	{
		/* We have an app name (good!) but no command line */
		CmdLineIsAppName = TRUE;
		lpCommandLine = (LPWSTR)lpApplicationName;
	}

	/* At this point the name has been toyed with enough to be openable */
	Status = BasepMapFile(lpApplicationName, &hSection, &ApplicationName);

	/* Check for failure */
	if (!NT_SUCCESS(Status))
	{
		/* Could be a non-PE File */
		switch (Status)
		{
			/* Check if the Kernel tells us it's not even valid MZ */
		case STATUS_INVALID_IMAGE_NE_FORMAT:
		case STATUS_INVALID_IMAGE_PROTECT:
		case STATUS_INVALID_IMAGE_NOT_MZ:

#if 0
			/* If it's a DOS app, use VDM */
			if ((BasepCheckDosApp(&ApplicationName)))
			{
				DPRINT1("Launching VDM...\n");
				RtlFreeHeap(RtlGetProcessHeap(), 0, NameBuffer);
				RtlFreeHeap(RtlGetProcessHeap(), 0, ApplicationName.Buffer);
				return CreateProcessW(L"ntvdm.exe",
					(LPWSTR)((ULONG_PTR)lpApplicationName), /* FIXME: Buffer must be writable!!! */
					lpProcessAttributes,
					lpThreadAttributes,
					bInheritHandles,
					dwCreationFlags,
					lpEnvironment,
					lpCurrentDirectory,
					&StartupInfo,
					lpProcessInformation);
			}
#endif
			/* It's a batch file */
			Extension = &ApplicationName.Buffer[ApplicationName.Length /
				sizeof(WCHAR) - 4];

			/* Make sure the extensions are correct */
			if (_wcsnicmp(Extension, L".bat", 4) && _wcsnicmp(Extension, L".cmd", 4))
			{
				SetLastError(ERROR_BAD_EXE_FORMAT);
				return FALSE;
			}

			/* Calculate the length of the command line */
			CmdLineLength = wcslen(CMD_STRING) + wcslen(lpCommandLine) + 1;

			/* If we found quotes, then add them into the length size */
			if (CmdLineIsAppName || FoundQuotes) CmdLineLength += 2;
			CmdLineLength *= sizeof(WCHAR);

			/* Allocate space for the new command line */
			BatchCommandLine = (LPWSTR)RtlAllocateHeap(RtlGetProcessHeap(),
				0,
				CmdLineLength);
			if (BatchCommandLine == NULL)
			{
				SetLastError(ERROR_NOT_ENOUGH_MEMORY);
				goto Cleanup;
			}

			/* Build it */
			wcscpy(BatchCommandLine, CMD_STRING);
			if (CmdLineIsAppName || FoundQuotes)
			{
				wcscat(BatchCommandLine, L"\"");
			}
			wcscat(BatchCommandLine, lpCommandLine);
			if (CmdLineIsAppName || FoundQuotes)
			{
				wcscat(BatchCommandLine, L"\"");
			}

			/* Create it as a Unicode String */
			RtlInitUnicodeString(&CommandLineString, BatchCommandLine);

			/* Set the command line to this */
			lpCommandLine = CommandLineString.Buffer;
			lpApplicationName = NULL;

			/* Free memory */
			RtlFreeHeap(RtlGetProcessHeap(), 0, ApplicationName.Buffer);
			ApplicationName.Buffer = NULL;
			goto GetAppName;
			break;

		case STATUS_INVALID_IMAGE_WIN_16:
			__debugbreak();
			/*
			// It's a Win16 Image, use VDM
			DPRINT1("Launching VDM...\n");
			RtlFreeHeap(RtlGetProcessHeap(), 0, NameBuffer);
			RtlFreeHeap(RtlGetProcessHeap(), 0, ApplicationName.Buffer);
			return CreateProcessW(L"ntvdm.exe",
			(LPWSTR)((ULONG_PTR)lpApplicationName), // FIXME: Buffer must be writable!!!
			lpProcessAttributes,
			lpThreadAttributes,
			bInheritHandles,
			dwCreationFlags,
			lpEnvironment,
			lpCurrentDirectory,
			&StartupInfo,
			lpProcessInformation);
			*/
		case STATUS_OBJECT_NAME_NOT_FOUND:
		case STATUS_OBJECT_PATH_NOT_FOUND:
			SetLastErrorByStatus(Status);
			goto Cleanup;

		default:
			/* Invalid Image Type */
			SetLastError(ERROR_BAD_EXE_FORMAT);
			goto Cleanup;
		}
	}

	/* Use our desktop if we didn't get any */
	if (!StartupInfo.lpDesktop)
	{
		StartupInfo.lpDesktop = OurPeb->ProcessParameters->DesktopInfo.Buffer;
	}

	/* FIXME: Check if Application is allowed to run */

	/* FIXME: Allow CREATE_SEPARATE only for WOW Apps, once we have that. */

	/* Get some information about the executable */
	Status = NtQuerySection(hSection,
		SectionImageInformation,
		&SectionImageInfo,
		sizeof(SectionImageInfo),
		NULL);
	if(!NT_SUCCESS(Status))
	{
		DPRINT1("Unable to get SectionImageInformation, status 0x%x\n", Status);
		SetLastErrorByStatus(Status);
		goto Cleanup;
	}

	/* Don't execute DLLs */
	if (SectionImageInfo.ImageCharacteristics & IMAGE_FILE_DLL)
	{
		DPRINT1("Can't execute a DLL\n");
		SetLastError(ERROR_BAD_EXE_FORMAT);
		goto Cleanup;
	}

	/* FIXME: Check for Debugger */

	/* FIXME: Check if Machine Type and SubSys Version Match */

	/* We don't support POSIX or anything else for now */
	if (IMAGE_SUBSYSTEM_WINDOWS_GUI != SectionImageInfo.SubSystemType &&
		IMAGE_SUBSYSTEM_WINDOWS_CUI != SectionImageInfo.SubSystemType)
	{
		DPRINT1("Invalid subsystem %d\n", SectionImageInfo.SubSystemType);
		SetLastError(ERROR_BAD_EXE_FORMAT);
		goto Cleanup;
	}

	if (IMAGE_SUBSYSTEM_WINDOWS_GUI == SectionImageInfo.SubSystemType)
	{
		/* Do not create a console for GUI applications */
		dwCreationFlags &= ~CREATE_NEW_CONSOLE;
		dwCreationFlags |= DETACHED_PROCESS;
	}

	/* Initialize the process object attributes */
	ObjectAttributes = BasepConvertObjectAttributes(&LocalObjectAttributes,
		lpProcessAttributes,
		NULL);

	/* Check if we're going to be debugged */
	if (dwCreationFlags & DEBUG_PROCESS)
	{
		/* FIXME: Set process flag */
	}

#if CHECK_DEBUGGING
	/* Check if we're going to be debugged */
	if (dwCreationFlags & (DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS))
	{
		/* Connect to DbgUi */
		Status = DbgUiConnectToDbg();
		if (!NT_SUCCESS(Status))
		{
			DPRINT1("Failed to connect to DbgUI!\n");
			SetLastErrorByStatus(Status);
			goto Cleanup;
		}

		/* Get the debug object */
		hDebug = DbgUiGetThreadDebugObject();

		/* Check if only this process will be debugged */
		if (dwCreationFlags & DEBUG_ONLY_THIS_PROCESS)
		{
			/* FIXME: Set process flag */
		}
	}
#endif

	/* Create the Process */
	Status = NtCreateProcess(&hProcess, PROCESS_ALL_ACCESS, ObjectAttributes, NtCurrentProcess(), (BOOLEAN)bInheritHandles, hSection, hDebug, NULL);
	if (!NT_SUCCESS(Status))
	{
		DPRINT1("Unable to create process, status 0x%x\n", Status);
		SetLastErrorByStatus(Status);
		goto Cleanup;
	}

	if (PriorityClass.PriorityClass != PROCESS_PRIORITY_CLASS_INVALID)
	{
		/* Set new class */
		Status = NtSetInformationProcess(hProcess, ProcessPriorityClass, &PriorityClass, sizeof(PROCESS_PRIORITY_CLASS));
		if(!NT_SUCCESS(Status))
		{
			DPRINT1("Unable to set new process priority, status 0x%x\n", Status);
			SetLastErrorByStatus(Status);
			goto Cleanup;
		}
	}

	/* Set Error Mode */
	if (dwCreationFlags & CREATE_DEFAULT_ERROR_MODE)
	{
		ULONG ErrorMode = SEM_FAILCRITICALERRORS;
		NtSetInformationProcess(hProcess, ProcessDefaultHardErrorMode, &ErrorMode, sizeof(ULONG));
	}

	/* Convert the directory to a full path */
	if (lpCurrentDirectory)
	{
		/* Allocate a buffer */
		CurrentDirectory = (LPWSTR)RtlAllocateHeap(RtlGetProcessHeap(), 0, (MAX_PATH + 1) * sizeof(WCHAR));
		if (CurrentDirectory == NULL)
		{
			DPRINT1("Cannot allocate memory for directory name\n");
			SetLastError(ERROR_NOT_ENOUGH_MEMORY);
			goto Cleanup;
		}

		/* Get the length */
		if (GetFullPathNameW(lpCurrentDirectory, MAX_PATH, CurrentDirectory, &CurrentDirectoryPart) > MAX_PATH)
		{
			DPRINT1("Directory name too long\n");
			SetLastError(ERROR_DIRECTORY);
			goto Cleanup;
		}
	}

	/* Insert quotes if needed */
	if (QuotesNeeded || CmdLineIsAppName)
	{
		/* Allocate a buffer */
		QuotedCmdLine = (LPWSTR)RtlAllocateHeap(RtlGetProcessHeap(), 0, (wcslen(lpCommandLine) + 2 + 1) * sizeof(WCHAR));
		if (QuotedCmdLine == NULL)
		{
			DPRINT1("Cannot allocate memory for quoted command line\n");
			SetLastError(ERROR_NOT_ENOUGH_MEMORY);
			goto Cleanup;
		}

		/* Copy the first quote */
		wcscpy(QuotedCmdLine, L"\"");

		/* Save a null char */
		if (QuotesNeeded)
		{
			SaveChar = *NullBuffer;
			*NullBuffer = UNICODE_NULL;
		}

		/* Add the command line and the finishing quote */
		wcscat(QuotedCmdLine, lpCommandLine);
		wcscat(QuotedCmdLine, L"\"");

		/* Add the null char */
		if (QuotesNeeded)
		{
			*NullBuffer = SaveChar;
			wcscat(QuotedCmdLine, NullBuffer);
		}

		DPRINT("Quoted CmdLine: %S\n", QuotedCmdLine);
	}

	if (Escape)
	{
		if (QuotedCmdLine == NULL)
		{
			QuotedCmdLine = (LPWSTR)RtlAllocateHeap(RtlGetProcessHeap(), 0, (wcslen(lpCommandLine) + 1) * sizeof(WCHAR));
			if (QuotedCmdLine == NULL)
			{
				SetLastError(ERROR_NOT_ENOUGH_MEMORY);
				goto Cleanup;
			}
			wcscpy(QuotedCmdLine, lpCommandLine);
		}

		ScanString = QuotedCmdLine;
		while (NULL != (ScanString = wcschr(ScanString, L'^')))
		{
			ScanString++;
			if (*ScanString == L'\"' || *ScanString == L'^' || *ScanString == L'\\')
			{
				memmove(ScanString-1, ScanString, wcslen(ScanString) * sizeof(WCHAR) + sizeof(WCHAR));
			}
		}
	}

	/* Get the Process Information */
	Status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &ProcessBasicInfo, sizeof(ProcessBasicInfo), NULL);

	/* Convert the environment */
	if(lpEnvironment && !(dwCreationFlags & CREATE_UNICODE_ENVIRONMENT))
	{
		lpEnvironment = BasepConvertUnicodeEnvironment(&EnvSize, lpEnvironment);
		if (!lpEnvironment) goto Cleanup;
	}

	/* Create Process Environment */
	RemotePeb = ProcessBasicInfo.PebBaseAddress;
	Status = BasepInitializeEnvironment(hProcess, RemotePeb, (LPWSTR)lpApplicationName, CurrentDirectory, (QuotesNeeded || CmdLineIsAppName || Escape) ? QuotedCmdLine : lpCommandLine, lpEnvironment, EnvSize, &StartupInfo, dwCreationFlags, bInheritHandles);

	/* Cleanup Environment */
	if (lpEnvironment && !(dwCreationFlags & CREATE_UNICODE_ENVIRONMENT))
	{
		RtlDestroyEnvironment(lpEnvironment);
	}

	if (!NT_SUCCESS(Status))
	{
		DPRINT1("Could not initialize Process Environment\n");
		SetLastErrorByStatus(Status);
		goto Cleanup;
	}

	/* Close the section */
	NtClose(hSection);
	hSection = NULL;

	/* Duplicate the handles if needed */
	if (!bInheritHandles && !(StartupInfo.dwFlags & STARTF_USESTDHANDLES) && SectionImageInfo.SubSystemType == IMAGE_SUBSYSTEM_WINDOWS_CUI)
	{
		PRTL_USER_PROCESS_PARAMETERS RemoteParameters;

		/* Get the remote parameters */
		Status = NtReadVirtualMemory(hProcess,
			&RemotePeb->ProcessParameters,
			&RemoteParameters,
			sizeof(PVOID),
			NULL);
		if (!NT_SUCCESS(Status))
		{
			DPRINT1("Failed to read memory\n");
			goto Cleanup;
		}

		/* Duplicate and write the handles */
		BasepDuplicateAndWriteHandle(hProcess, OurPeb->ProcessParameters->StandardInput, &RemoteParameters->StandardInput);
		BasepDuplicateAndWriteHandle(hProcess, OurPeb->ProcessParameters->StandardOutput, &RemoteParameters->StandardOutput);
		BasepDuplicateAndWriteHandle(hProcess, OurPeb->ProcessParameters->StandardError, &RemoteParameters->StandardError);
	}

	/* Notify CSRSS */
	Status = BasepNotifyCsrOfCreation(dwCreationFlags, (HANDLE)ProcessBasicInfo.UniqueProcessId, bInheritHandles);

	if (!NT_SUCCESS(Status))
	{
		DPRINT1("CSR Notification Failed");
		SetLastErrorByStatus(Status);
		goto Cleanup;
	}

	/* Create the first thread */
	DPRINT("Creating thread for process (EntryPoint = 0x%p)\n",
		SectionImageInfo.TransferAddress);
	hThread = BasepCreateFirstThread(hProcess, lpThreadAttributes, &SectionImageInfo, &ClientId);

	if (hThread == NULL)
	{
		DPRINT1("Could not create Initial Thread\n");
		/* FIXME - set last error code */
		goto Cleanup;
	}

	if (!(dwCreationFlags & CREATE_SUSPENDED))
	{
		NtResumeThread(hThread, &Dummy);
	}

	/* Return Data */
	lpProcessInformation->dwProcessId = (DWORD)ClientId.UniqueProcess;
	lpProcessInformation->dwThreadId = (DWORD)ClientId.UniqueThread;
	lpProcessInformation->hProcess = hProcess;
	lpProcessInformation->hThread = hThread;
	DPRINT("hThread[%p]: %p inside hProcess[%p]: %p\n", hThread,
		ClientId.UniqueThread, ClientId.UniqueProcess, hProcess);
	hProcess = hThread = NULL;
	Ret = TRUE;

Cleanup:
	/* De-allocate heap strings */
	if (NameBuffer) RtlFreeHeap(RtlGetProcessHeap(), 0, NameBuffer);
	if (ApplicationName.Buffer)
		RtlFreeHeap(RtlGetProcessHeap(), 0, ApplicationName.Buffer);
	if (CurrentDirectory) RtlFreeHeap(RtlGetProcessHeap(), 0, CurrentDirectory);
	if (QuotedCmdLine) RtlFreeHeap(RtlGetProcessHeap(), 0, QuotedCmdLine);

	/* Kill any handles still alive */
	if (hSection) NtClose(hSection);
	if (hThread)
	{
		/* We don't know any more details then this */
		NtTerminateProcess(hProcess, STATUS_UNSUCCESSFUL);
		NtClose(hThread);
	}
	if (hProcess) NtClose(hProcess);

	/* Return Success */
	return Ret;
}

#endif

int __stdcall foo(int n)
{
	return n > 0 ? foo(n - 1) + foo(n - 2) : 0;
}



void _tmain(int argc, TCHAR* argv[])
{
	foo(0);
	STARTUPINFO si = {};
	si.cb = sizeof(si);
	PROCESS_INFORMATION pi;
	WCHAR name[] = _T("C:\\Windows\\Notepad.exe");
	//PWSTR name = (PWSTR)calloc(32 * 1024, sizeof(WCHAR)); _tcscpy(name, _T("C:\\Windows\\SysWOW64\\Notepad.exe"));
	CreateProcessW(NULL, name, NULL, NULL, FALSE, CREATE_DEFAULT_ERROR_MODE | DETACHED_PROCESS, NULL, NULL, &si, &pi);
}