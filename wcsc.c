/*+===================================================================
  File:    wcsc.c

  Summary: Windows Certificate Store Combiner
           See README.md for a functional description of this program.

  Origin:  Initial version authored and published by Oddbjørn Kvalsund
           on https://github.com/oddbjornkvalsund/wcsc July 2018.

  TODOs:
           - Rename to "Windows Certificate Store Aggregator"

  Copyright Oddbjørn Kvalsund <oddbjorn.kvalsund@gmail.com> 2018
===================================================================+*/

#define UNICODE
#define MAX_NUM_CERT_STORES 32

#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>

#include "detours.h"

#pragma comment(lib, "Detours")
#pragma comment(lib, "Crypt32")

typedef struct
{
    LPCSTR aName;
    LPCWSTR wName;
    HCERTSTORE hCurrentUserStore;
    HCERTSTORE hLocalMachineStore;
    HCERTSTORE hCollectionStore;
} NAMEDHCERTSTORE;

static int numCertStores = 0;
static NAMEDHCERTSTORE aCertStores[MAX_NUM_CERT_STORES];

// Function pointers to original functions for use by Microsoft Detours
static HCERTSTORE(WINAPI *TrueCertOpenSystemStoreA)(
    HCRYPTPROV_LEGACY hProv,
    LPCSTR szSubsystemProtocol) = CertOpenSystemStoreA;

static HCERTSTORE(WINAPI *TrueCertOpenSystemStoreW)(
    HCRYPTPROV_LEGACY hProv,
    LPCWSTR szSubsystemProtocol) = CertOpenSystemStoreW;

static BOOL(WINAPI *TrueCertCloseStore)(
    HCERTSTORE hCertStore,
    DWORD dwFlags) = CertCloseStore;

// Local function declarations
void ErrorExit(LPCWSTR);

// Create a new certificate collection store and and add existing collections to it
HCERTSTORE createCollectionStore(HCERTSTORE hStoreA, HCERTSTORE hStoreB)
{
    HCERTSTORE hCollectionStore = CertOpenStore(CERT_STORE_PROV_COLLECTION, 0, (HCRYPTPROV_LEGACY)NULL, 0, NULL);
    if (!hCollectionStore)
    {
        ErrorExit(L"CertOpenStore in createCollectionStore");
    }

    if (!CertAddStoreToCollection(hCollectionStore, hStoreA, 0, 0))
    {
        ErrorExit(L"CertAddStoreToCollection(hStoreA) in createCollectionStore");
    }

    if (!CertAddStoreToCollection(hCollectionStore, hStoreB, 0, 0))
    {
        ErrorExit(L"CertAddStoreToCollection(hStoreB) in createCollectionStore");
    }

    return hCollectionStore;
}

// Detour function for CertOpenSystemStoreA
HCERTSTORE WINAPI MyCertOpenSystemStoreA(HCRYPTPROV_LEGACY hProv, LPCSTR szSubsystemProtocol)
{
    // Check if the specified store has already been opened
    for (int i = 0; i < numCertStores; i++)
    {
        LPCSTR name = aCertStores[i].aName;
        if (name != NULL && _stricmp(name, szSubsystemProtocol) == 0)
        {
            return aCertStores[i].hCollectionStore;
        }
    }

    // The cache array aCertStores is of a static size, so make sure we don't write past the end of it
    if (numCertStores == MAX_NUM_CERT_STORES)
    {
        ErrorExit(L"Max number of certificate stores opened!");
    }

    NAMEDHCERTSTORE *certStore = &(aCertStores[numCertStores++]);
    certStore->aName = _strdup(szSubsystemProtocol);
    certStore->wName = NULL;
    certStore->hCurrentUserStore = CertOpenStore(
        CERT_STORE_PROV_SYSTEM_A,
        0,
        (HCRYPTPROV_LEGACY)NULL,
        CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_READONLY_FLAG,
        szSubsystemProtocol);
    if (!certStore->hCurrentUserStore)
    {
        ErrorExit(L"CertOpenStore for CERT_SYSTEM_STORE_CURRENT_USER in MyCertOpenSystemStoreA");
    }
    certStore->hLocalMachineStore = CertOpenStore(
        CERT_STORE_PROV_SYSTEM_A,
        0,
        (HCRYPTPROV_LEGACY)NULL,
        CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_READONLY_FLAG,
        szSubsystemProtocol);
    if (!certStore->hLocalMachineStore)
    {
        ErrorExit(L"CertOpenStore for CERT_SYSTEM_STORE_LOCAL_MACHINE in MyCertOpenSystemStoreA");
    }
    certStore->hCollectionStore = createCollectionStore(certStore->hCurrentUserStore, certStore->hLocalMachineStore);

    return certStore->hCollectionStore;
}

// Detour function for CertOpenSystemStoreW
HCERTSTORE WINAPI MyCertOpenSystemStoreW(HCRYPTPROV_LEGACY hProv, LPCWSTR szSubsystemProtocol)
{
    // Check if the specified store has already been opened
    for (int i = 0; i < numCertStores; i++)
    {
        LPCWSTR name = aCertStores[i].wName;
        if (name != NULL && _wcsicmp(name, szSubsystemProtocol) == 0)
        {
            return aCertStores[i].hCollectionStore;
        }
    }

    // The cache array aCertStores is of a static size, so make sure we don't write past the end of it
    if (numCertStores == MAX_NUM_CERT_STORES)
    {
        ErrorExit(L"Max number of certificate stores opened!");
    }

    // Initialize new store
    NAMEDHCERTSTORE *certStore = &(aCertStores[numCertStores++]);
    certStore->aName = NULL;
    certStore->wName = _wcsdup(szSubsystemProtocol);
    certStore->hCurrentUserStore = CertOpenStore(
        CERT_STORE_PROV_SYSTEM_W,
        0,
        (HCRYPTPROV_LEGACY)NULL,
        CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_READONLY_FLAG,
        szSubsystemProtocol);
    if (!certStore->hCurrentUserStore)
    {
        ErrorExit(L"CertOpenStore for CERT_SYSTEM_STORE_CURRENT_USER in MyCertOpenSystemStoreW");
    }
    certStore->hLocalMachineStore = CertOpenStore(
        CERT_STORE_PROV_SYSTEM_W,
        0,
        (HCRYPTPROV_LEGACY)NULL,
        CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_READONLY_FLAG,
        szSubsystemProtocol);
    if (!certStore->hLocalMachineStore)
    {
        ErrorExit(L"CertOpenStore for CERT_SYSTEM_STORE_LOCAL_MACHINE in MyCertOpenSystemStoreW");
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
        if(aCertStores[i].aName != NULL) {
            free((void *)aCertStores[i].aName);
        }
        if(aCertStores[i].wName != NULL) {
            free((void *)aCertStores[i].wName);
        }
    }
    numCertStores = 0;
}

// Print last error to stderr and exit with the corresponding error code
void ErrorExit(LPCWSTR lpszFunction)
{
    DWORD dwError = GetLastError();
    LPWSTR lpszErrorBuffer = NULL;
    FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        dwError,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPWSTR)&lpszErrorBuffer,
        0,
        NULL);
    fwprintf(stderr, L"Error calling %s: %s\n", lpszFunction, lpszErrorBuffer);
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
        DetourAttach((VOID *)&TrueCertOpenSystemStoreA, MyCertOpenSystemStoreA);
        DetourAttach((VOID *)&TrueCertOpenSystemStoreW, MyCertOpenSystemStoreW);
        DetourAttach((VOID *)&TrueCertCloseStore, MyCertCloseStore);
        if (DetourTransactionCommit() != NO_ERROR)
        {
            ErrorExit(L"DetourTransactionCommit on attach");
        }
    }
    else if (dwReason == DLL_PROCESS_DETACH)
    {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach((VOID *)&TrueCertOpenSystemStoreA, MyCertOpenSystemStoreA);
        DetourDetach((VOID *)&TrueCertOpenSystemStoreW, MyCertOpenSystemStoreW);
        DetourDetach((VOID *)&TrueCertCloseStore, MyCertCloseStore);
        if (DetourTransactionCommit() != NO_ERROR)
        {
            ErrorExit(L"DetourTransactionCommit on detach");
        }
        closeAllCertificateStores();
    }

    return TRUE;
}