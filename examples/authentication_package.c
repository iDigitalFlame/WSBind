#define _WIN32_WINNT 0x0501

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <ntsecapi.h>

typedef PVOID *PLSA_CLIENT_REQUEST;
typedef PVOID *PLSA_DISPATCH_TABLE;
typedef struct _SECPKG_PRIMARY_CRED {
  LUID           LogonId;
  UNICODE_STRING DownlevelName;
  UNICODE_STRING DomainName;
  UNICODE_STRING Password;
  UNICODE_STRING OldPassword;
  PSID           UserSid;
  ULONG          Flags;
  UNICODE_STRING DnsDomainName;
  UNICODE_STRING Upn;
  UNICODE_STRING LogonServer;
  UNICODE_STRING Spare1;
  UNICODE_STRING Spare2;
  UNICODE_STRING Spare3;
  UNICODE_STRING Spare4;
} SECPKG_PRIMARY_CRED, *PSECPKG_PRIMARY_CRED;
typedef struct _SECPKG_SUPPLEMENTAL_CRED {
  UNICODE_STRING PackageName;
  ULONG          CredentialSize;
  PUCHAR         Credentials;
} SECPKG_SUPPLEMENTAL_CRED, *PSECPKG_SUPPLEMENTAL_CRED;
typedef struct _SECPKG_SUPPLEMENTAL_CRED_ARRAY {
  ULONG                    CredentialCount;
  SECPKG_SUPPLEMENTAL_CRED Credentials[1];
} SECPKG_SUPPLEMENTAL_CRED_ARRAY, *PSECPKG_SUPPLEMENTAL_CRED_ARRAY;
typedef enum _LSA_TOKEN_INFORMATION_TYPE {
  LsaTokenInformationNull,
  LsaTokenInformationV1,
  LsaTokenInformationV2,
  LsaTokenInformationV3
} LSA_TOKEN_INFORMATION_TYPE, *PLSA_TOKEN_INFORMATION_TYPE;



void trigger(char* name) {
    unsigned char* n = calloc(strlen(name)+8, 1);
    sprintf(n, "C:\\%s.txt\0", name);

    FILE* f = fopen(n, "a");
    if(f == NULL) {
        return;
    }
    fprintf(f, "trig-%d\n\0", time(NULL));
    fclose(f);

    free(n);
}

__declspec(dllexport) void LsaApLogonTerminated(PLUID LogonId) {
    trigger("LsaApLogonTerminated");
}
__declspec(dllexport) BOOL WINAPI DllMain(HINSTANCE hiDLL, DWORD dwReason, LPVOID lpReserved) {
    trigger("DllMain");
    return TRUE;
}
__declspec(dllexport) NTSTATUS LsaApInitializePackage(ULONG AuthenticationPackageId, PLSA_DISPATCH_TABLE LsaDispatchTable, PLSA_STRING Database, PLSA_STRING Confidentiality, PLSA_STRING *AuthenticationPackageName) {
    trigger("LsaApInitializePackage");
    return 0;
}
__declspec(dllexport) NTSTATUS LsaCallAuthenticationPackage(HANDLE LsaHandle,ULONG AuthenticationPackage, PVOID ProtocolSubmitBuffer, ULONG SubmitBufferLength, PVOID *ProtocolReturnBuffer, PULONG ReturnBufferLength, PNTSTATUS ProtocolStatus) {
    trigger("LsaCallAuthenticationPackage");
    return 0;
}
__declspec(dllexport) NTSTATUS LsaApCallPackage(PLSA_CLIENT_REQUEST ClientRequest, PVOID ProtocolSubmitBuffer, PVOID ClientBufferBase, ULONG SubmitBufferLength, PVOID *ProtocolReturnBuffer, PULONG ReturnBufferLength, PNTSTATUS ProtocolStatus) {
    trigger("LsaApCallPackage");
    return 0;
}
__declspec(dllexport) NTSTATUS LsaApCallPackageUntrusted(PLSA_CLIENT_REQUEST ClientRequest, PVOID ProtocolSubmitBuffer, PVOID ClientBufferBase, ULONG SubmitBufferLength, PVOID *ProtocolReturnBuffer, PULONG ReturnBufferLength, PNTSTATUS ProtocolStatus) {
    trigger("LsaApCallPackageUntrusted");
    return 0;
}
__declspec(dllexport) NTSTATUS LsaApCallPackagePassthrough(PLSA_CLIENT_REQUEST ClientRequest, PVOID ProtocolSubmitBuffer, PVOID ClientBufferBase, ULONG SubmitBufferLength, PVOID *ProtocolReturnBuffer, PULONG ReturnBufferLength, PNTSTATUS ProtocolStatus) {
    trigger("LsaApCallPackagePassthrough");
    return 0;
}
__declspec(dllexport) NTSTATUS LsaApLogonUser(PLSA_CLIENT_REQUEST ClientRequest, SECURITY_LOGON_TYPE LogonType, PVOID AuthenticationInformation, PVOID ClientAuthenticationBase, ULONG AuthenticationInformationLength, PVOID *ProfileBuffer, PULONG ProfileBufferLength, PLUID LogonId, PNTSTATUS SubStatus, PLSA_TOKEN_INFORMATION_TYPE TokenInformationType, PVOID *TokenInformation, PLSA_UNICODE_STRING *AccountName, PLSA_UNICODE_STRING *AuthenticatingAuthority) {
    trigger("LsaApLogonUser");
    return 0;
}
__declspec(dllexport) NTSTATUS LsaApLogonUserEx(PLSA_CLIENT_REQUEST ClientRequest, SECURITY_LOGON_TYPE LogonType, PVOID AuthenticationInformation, PVOID ClientAuthenticationBase, ULONG AuthenticationInformationLength, PVOID *ProfileBuffer, PULONG ProfileBufferLength, PLUID LogonId, PNTSTATUS SubStatus, PLSA_TOKEN_INFORMATION_TYPE TokenInformationType, PVOID *TokenInformation, PUNICODE_STRING *AccountName, PUNICODE_STRING *AuthenticatingAuthority, PUNICODE_STRING *MachineName) {
    trigger("LsaApLogonUserEx");
    return 0;
}
__declspec(dllexport) NTSTATUS LsaApLogonUserEx2(PLSA_CLIENT_REQUEST ClientRequest, SECURITY_LOGON_TYPE LogonType, PVOID ProtocolSubmitBuffer, PVOID ClientBufferBase, ULONG SubmitBufferSize, PVOID *ProfileBuffer, PULONG ProfileBufferSize, PLUID LogonId, PNTSTATUS SubStatus, PLSA_TOKEN_INFORMATION_TYPE TokenInformationType, PVOID *TokenInformation, PUNICODE_STRING *AccountName, PUNICODE_STRING *AuthenticatingAuthority, PUNICODE_STRING *MachineName, PSECPKG_PRIMARY_CRED PrimaryCredentials, PSECPKG_SUPPLEMENTAL_CRED_ARRAY *SupplementalCredentials) {
    trigger("LsaApLogonUserEx2");
    return 0;
}
