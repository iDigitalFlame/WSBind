#// Copyright (C) 2020 iDigitalFlame
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

#include "../wsbind.h"

int main(int argc, char **argv)
{
    printf("Start 1\n");
    typedef struct _UNICODE_STRING {
        USHORT Length;
        USHORT MaximumLength;
        PWCH   Buffer;
    } UNICODE_STRING, *PUNICODE_STRING;

    printf("Start 2\n");

    typedef struct _OBJECT_ATTRIBUTES {
        ULONG           Length;
        HANDLE          RootDirectory;
        PUNICODE_STRING ObjectName;
        ULONG           Attributes;
        PVOID           SecurityDescriptor;
        PVOID           SecurityQualityOfService;
    } OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

    printf("Start 3\n");

    typedef DWORD (WINAPI *funcZwCreateProcess) (
        PHANDLE ProcessHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
        HANDLE ParentProcess,
        BOOLEAN InheritObjectTable,
        HANDLE SectionHandle OPTIONAL,
        HANDLE DebugPort OPTIONAL,
        HANDLE ExceptionPort OPTIONAL
    );

/*
    NTSYSAPI NTSTATUS ZwCreateSection(
        PHANDLE            SectionHandle,
        ACCESS_MASK        DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        PLARGE_INTEGER     MaximumSize,
        ULONG              SectionPageProtection,
        ULONG              AllocationAttributes,
        HANDLE             FileHandle
);*/
    typedef DWORD (WINAPI *funcZwCreateSection) (
        PHANDLE            SectionHandle,
        ACCESS_MASK        DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        PLARGE_INTEGER     MaximumSize,
        ULONG              SectionPageProtection,
        ULONG              AllocationAttributes,
        HANDLE             FileHandle
    );

    printf("Start 4\n");

    HMODULE mod = GetModuleHandle("ntdll.dll");

    printf("Start 5\n");

    if(mod == NULL) {
        printf("Nope!\n");
        return 1;
    }

    printf("Start 6\n");

    funcZwCreateProcess zCw = (funcZwCreateProcess)GetProcAddress(mod, "ZwCreateProcess");
    funcZwCreateSection zCs = (funcZwCreateSection)GetProcAddress(mod, "ZwCreateSection");

    if (zCw == NULL) {
        printf("Start 7 (Func Failed)\n");
        return 1;
    }

    if (zCs == NULL) {
        printf("Start 7 (Func Failed)\n");
        return 1;
    }


    printf("Start 7: Handle: %d %d\n", zCw, zCs);


    printf("Start 8\n");

    /*

    NTSTATUS NTAPI NtCreateUserProcess(
	PHANDLE ProcessHandle,
	PHANDLE ThreadHandle,
	ACCESS_MASK ProcessDesiredAccess,
	ACCESS_MASK ThreadDesiredAccess,
	POBJECT_ATTRIBUTES ProcessObjectAttributes,
	POBJECT_ATTRIBUTES ThreadObjectAttributes,
	ULONG ProcessFlags,
	ULONG ThreadFlags,
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
	PPROCESS_CREATE_INFO CreateInfo,
	PPROCESS_ATTRIBUTE_LIST AttributeList
	);

    */

    typedef DWORD (WINAPI *funcZwCreateSection) (
        PHANDLE ProcessHandle,
        PHANDLE ThreadHandle,
        ACCESS_MASK ProcessDesiredAccess,
        ACCESS_MASK ThreadDesiredAccess,
        POBJECT_ATTRIBUTES ProcessObjectAttributes,
        POBJECT_ATTRIBUTES ThreadObjectAttributes,
        ULONG ProcessFlags,
        ULONG ThreadFlags,
        PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
        PPROCESS_CREATE_INFO CreateInfo,
        PPROCESS_ATTRIBUTE_LIST AttributeList
    );


	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;

	int l = NtCreateUserProcess(&hProcess, &hThread, MAXIMUM_ALLOWED, MAXIMUM_ALLOWED, NULL, NULL, 0x00000100, 0x00000001, NULL, NULL, NULL);

    printf("Result: %u\n", l);
/*

NTSTATUS NTAPI NtCreateUserProcess(
	PHANDLE ProcessHandle,
	PHANDLE ThreadHandle,
	ACCESS_MASK ProcessDesiredAccess,
	ACCESS_MASK ThreadDesiredAccess,
	POBJECT_ATTRIBUTES ProcessObjectAttributes,
	POBJECT_ATTRIBUTES ThreadObjectAttributes,
	ULONG ProcessFlags,
	ULONG ThreadFlags,
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
	PPROCESS_CREATE_INFO CreateInfo,
	PPROCESS_ATTRIBUTE_LIST AttributeList
	);
    */

/*
    //int v = wsp_execv("ping -n 10 127.0.0.1", NULL, 1);

    HANDLE f = NULL; //= //CreateFile("C:\\Windows\\notepad.exe", GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    f = CreateFileA("C:\\Windows\\explorer.exe", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | SECURITY_IMPERSONATION, NULL);
    //NtCreateSection(&sectionHandle, SECTION_ALL_ACCESS, ...);
    //NtCreateProcess(&processHandle, PROCESS_ALL_ACCESS, NULL, GetCurrentProcess(), FALSE, sectionHandle, NULL, NULL);

    DWORD k = GetLastError();

    printf("Started [%d] %d\n", f, k);



    HANDLE exp = GetCurrentProcess(); //OpenProcess(PROCESS_ALL_ACCESS, FALSE, NULL);
    HANDLE thread = NULL;
    HANDLE section = NULL;

    printf("Start 9: %u\n", exp);

    DWORD r1 = zCs(&section, SECTION_ALL_ACCESS, NULL, 1000000, PAGE_EXECUTE, SEC_IMAGE, f);

    DWORD xx = GetLastError();
     printf("Started [%u] %d\n", r1, xx);

    DWORD res = zCw(&thread, PROCESS_ALL_ACCESS, NULL, exp, FALSE, NULL, NULL, NULL);



    printf("Start 10: %u %u %u %u\n", res, thread, r1, section);

    CloseHandle(exp);
    CloseHandle(f);

    printf("Start 11\n");

    DWORD res2 = ResumeThread(exp);

    printf("Start 12: %u\n", res2);

    sleep(10);

    CloseHandle(thread);

    printf("Start 13\n");
    //wsp_execv("ping -n 10 127.0.0.1", NULL, 1);


/*    HANDLE pT = NULL;

    printf("WHat1? %s - %s\n", zCw);
    HANDLE z = OpenProcess(PROCESS_ALL_ACCESS, FALSE, 4124);


    printf("WHat? %s - %s\n", zCw, z);
    DWORD p = zCw(&pT, 0x000F0000, NULL, z, FALSE, NULL, NULL, NULL);
    if(!zCw) {
        printf("Nope 1\n");
        return 1;
    }
    wsp_execv("ping -n 10 127.0.0.1", NULL, 1);
    sleep(10); */
    return 0;
}

/*
ZwCreateProcess(
    OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN HANDLE ParentProcess,
    IN BOOLEAN InheritObjectTable,
    IN HANDLE SectionHandle OPTIONAL,
    IN HANDLE DebugPort OPTIONAL,
    IN HANDLE ExceptionPort OPTIONAL
    );*/
