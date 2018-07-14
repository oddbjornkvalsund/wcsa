/*+===================================================================
  File:      wcsc.c

  Summary:   Brief summary of the file contents and purpose.

  Classes:   Classes declared or used (in source files).

  Functions: Functions exported (in source files).

  Origin:    Indications of where content may have come from. This
             is not a change history but rather a reference to the
             editor-inheritance behind the content or other
             indications about the origin of the source.
## 

  Copyright Oddbjørn Kvalsund <oddbjorn.kvalsund@gmail.com> 2018
===================================================================+*/
#include <stdio.h>
#include <windows.h>
#include <tchar.h>
#include <wincrypt.h>

#include "detours.h"

#pragma comment(lib, "Detours")
#pragma comment(lib, "Crypt32")

// Keep reference to original function

static HCERTSTORE(WINAPI *TrueCertOpenSystemStore)(
    HCRYPTPROV_LEGACY hProv,
    LPCSTR szSubsystemProtocol) = CertOpenSystemStore;

// Helper functions

void ErrorExit(LPTSTR lpszFunction)
{
    DWORD dwError = GetLastError();
    LPTSTR lpszErrorBuffer = NULL;
    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        dwError,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR)&lpszErrorBuffer,
        0,
        NULL);
    printf("Error calling %s: %s\n", lpszFunction, lpszErrorBuffer);
    LocalFree(lpszErrorBuffer);
    ExitProcess(dwError);
}

HCERTSTORE openExistingStore(DWORD dwFlags)
{
    HCERTSTORE hStore = CertOpenStore(
        CERT_STORE_PROV_SYSTEM,
        0,
        (HCRYPTPROV_LEGACY)NULL,
        dwFlags | CERT_STORE_READONLY_FLAG,
        L"MY");
    if (!hStore)
    {
        ErrorExit("CertOpenStore in openExistingStore");
    }

    return hStore;
}

HCERTSTORE createCollectionStore(HCERTSTORE hStoreA, HCERTSTORE hStoreB)
{
    HCERTSTORE hCollectionStore = CertOpenStore(CERT_STORE_PROV_COLLECTION, 0, (HCRYPTPROV_LEGACY)NULL, 0, NULL);
    if (!hCollectionStore)
    {
        ErrorExit("CertOpenStore in createCollectionStore");
    }

    if (!CertAddStoreToCollection(hCollectionStore, hStoreA, 0, 0))
    {
        ErrorExit("CertAddStoreToCollection(hStoreA) in createCollectionStore");
    }

    if (!CertAddStoreToCollection(hCollectionStore, hStoreB, 0, 0))
    {
        ErrorExit("CertAddStoreToCollection(hStoreB) in createCollectionStore");
    }

    return hCollectionStore;
}

// Replacement function

static HCERTSTORE hCurrentUserStore;
static HCERTSTORE hLocalMachineStore;
static HCERTSTORE hCollectionStore;

HCERTSTORE WINAPI MyCertOpenSystemStore(HCRYPTPROV_LEGACY hProv, LPCSTR szSubsystemProtocol)
{
    return hCollectionStore; // We should probably intercept CertCloseStore() and check for attempts to close hCollectionStore
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved)
{
    if (DetourIsHelperProcess())
    {
        return TRUE;
    }

    if (dwReason == DLL_PROCESS_ATTACH)
    {
        DetourRestoreAfterWith();
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        hCurrentUserStore = openExistingStore(CERT_SYSTEM_STORE_CURRENT_USER);
        hLocalMachineStore = openExistingStore(CERT_SYSTEM_STORE_LOCAL_MACHINE);
        hCollectionStore = createCollectionStore(hCurrentUserStore, hLocalMachineStore);

        DetourAttach((VOID *)&TrueCertOpenSystemStore, MyCertOpenSystemStore);
        LONG error = DetourTransactionCommit();
        if (error != NO_ERROR)
        {
            ErrorExit("DetourTransactionCommit on attach");
        }
    }
    else if (dwReason == DLL_PROCESS_DETACH)
    {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach((VOID *)&TrueCertOpenSystemStore, MyCertOpenSystemStore);
        LONG error = DetourTransactionCommit();
        if (error != NO_ERROR)
        {
            ErrorExit("DetourTransactionCommit on detach");
        }
        CertCloseStore(hCollectionStore, 0);
        CertCloseStore(hLocalMachineStore, 0);
        CertCloseStore(hCurrentUserStore, 0);
    }

    return TRUE;
}