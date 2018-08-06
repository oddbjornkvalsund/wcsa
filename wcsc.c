/*+===================================================================
  File:    wcsc.c

  Summary: Windows Certificate Store Combiner
           See README.md for a functional description of this program.

  Origin:  Initial version authored and published by Oddbjørn Kvalsund
           on https://github.com/oddbjornkvalsund/wcsc July 2018.

  TODOs:
           - Rename to "Windows Certificate Store Aggregator"
           - Handle Unicode properly; CertOpenSystemStoreA vs CertOpenSystemStoreW.

  Copyright Oddbjørn Kvalsund <oddbjorn.kvalsund@gmail.com> 2018
===================================================================+*/
#include <stdio.h>
#include <windows.h>
#include <tchar.h>
#include <wincrypt.h>

#include "detours.h"

#pragma comment(lib, "Detours")
#pragma comment(lib, "Crypt32")

#define MAX_NUM_CERT_STORES 32

typedef struct
{
    LPTSTR lpszName;
    HCERTSTORE hCurrentUserStore;
    HCERTSTORE hLocalMachineStore;
    HCERTSTORE hCollectionStore;
} NAMEDHCERTSTORE;

static int numCertStores = 0;
static NAMEDHCERTSTORE aCertStores[MAX_NUM_CERT_STORES];

// Function pointers to original functions for use by Microsoft Detours
static HCERTSTORE(WINAPI *TrueCertOpenSystemStore)(
    HCRYPTPROV_LEGACY hProv,
    LPCSTR szSubsystemProtocol) = CertOpenSystemStore;

static BOOL(WINAPI *TrueCertCloseStore)(
    HCERTSTORE hCertStore,
    DWORD dwFlags) = CertCloseStore;

// Local function declarations
void ErrorExit(LPTSTR);

// Create a new certificate collection store and and add existing collections to it
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

// Detour function for CertOpenSystemStore
HCERTSTORE WINAPI MyCertOpenSystemStore(HCRYPTPROV_LEGACY hProv, LPCSTR szSubsystemProtocol)
{
    // Check if the specified store has already been opened
    for (int i = 0; i < numCertStores; i++)
    {
        if (_stricmp(aCertStores[i].lpszName, szSubsystemProtocol) == 0)
        {
            return aCertStores[i].hCollectionStore;
        }
    }

    // The cache array aCertStores is of a static size, so make sure we don't write past the end of it
    if (numCertStores == MAX_NUM_CERT_STORES)
    {
        ErrorExit("Max number of certificate stores opened!");
    }

    // Convert szSubsystemProtocol (LPCSTR) to multi-byte (LPWSTR) for use with CertOpenStore
    wchar_t wszSubsystemProtocol[64];
    MultiByteToWideChar(CP_ACP, 0, szSubsystemProtocol, -1, (LPWSTR)wszSubsystemProtocol, 64);

    // Initialize new store
    NAMEDHCERTSTORE *certStore = &(aCertStores[numCertStores++]);
    certStore->lpszName = strdup(szSubsystemProtocol);
    certStore->hCurrentUserStore = CertOpenStore(
        CERT_STORE_PROV_SYSTEM,
        0,
        (HCRYPTPROV_LEGACY)NULL,
        CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_READONLY_FLAG,
        wszSubsystemProtocol);
    if (!certStore->hCurrentUserStore)
    {
        ErrorExit("CertOpenStore for CERT_SYSTEM_STORE_CURRENT_USER in MyCertOpenSystemStore");
    }
    certStore->hLocalMachineStore = CertOpenStore(
        CERT_STORE_PROV_SYSTEM,
        0,
        (HCRYPTPROV_LEGACY)NULL,
        CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_READONLY_FLAG,
        wszSubsystemProtocol);
    if (!certStore->hLocalMachineStore)
    {
        ErrorExit("CertOpenStore for CERT_SYSTEM_STORE_LOCAL_MACHINE in MyCertOpenSystemStore");
    }
    certStore->hCollectionStore = createCollectionStore(certStore->hCurrentUserStore, certStore->hLocalMachineStore);

    return certStore->hCollectionStore;
}

// Detour function for CertCloseStore
BOOL WINAPI MyCertCloseStore(HCERTSTORE hCertStore, DWORD dwFlags)
{
    for (int i = 0; i < numCertStores; i++)
    {
        if (hCertStore == aCertStores[i].hCollectionStore)
        {
            return TRUE; // Do nothing, fake success
        }
    }

    return TrueCertCloseStore(hCertStore, dwFlags);
}

// Close all certificate store handles held by this program
void closeAllCertificateStores()
{
    for (int i = 0; i < numCertStores; i++)
    {
        TrueCertCloseStore(aCertStores[i].hCollectionStore, 0);
        TrueCertCloseStore(aCertStores[i].hLocalMachineStore, 0);
        TrueCertCloseStore(aCertStores[i].hCurrentUserStore, 0);
    }
    numCertStores = 0;
}

// Print last error to stderr and exit with the corresponding error code
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
    fprintf(stderr, "Error calling %s: %s\n", lpszFunction, lpszErrorBuffer);
    closeAllCertificateStores();
    LocalFree(lpszErrorBuffer);
    ExitProcess(dwError);
}

// The main dll function exported with ordinal 1 (as defined in wcsc.def)
// making it suitable for use with the Microsoft Detours 'withdll' utility
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
        DetourAttach((VOID *)&TrueCertOpenSystemStore, MyCertOpenSystemStore);
        DetourAttach((VOID *)&TrueCertCloseStore, MyCertCloseStore);
        if (DetourTransactionCommit() != NO_ERROR)
        {
            ErrorExit("DetourTransactionCommit on attach");
        }
    }
    else if (dwReason == DLL_PROCESS_DETACH)
    {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach((VOID *)&TrueCertOpenSystemStore, MyCertOpenSystemStore);
        DetourDetach((VOID *)&TrueCertCloseStore, MyCertCloseStore);
        if (DetourTransactionCommit() != NO_ERROR)
        {
            ErrorExit("DetourTransactionCommit on detach");
        }
        closeAllCertificateStores();
    }

    return TRUE;
}