# Windows Certificate Store Aggregator
> Tooling to read certificate stores in Windows for Java versions < 19 (2022)

-----
The [JDK-6782021][jdkbug] issue that was reported in 2008 was finally fixed with Java 19, so this is no longer an issue for modern Java versions 🥳

-----

## Problem
The `SunMSCAPI` JCA provider[¹][mscapi] used by both Oracle JDK/JRE and OpenJDK only provides access to certificates and private keys stored in the `Current User` certificate store. The reason for this is that it uses the `CertOpenSystemStore` WinCrypt API call that explicitly states[²][wincrypt]:

> Only current user certificates are accessible using this method, not the local machine store.

So if you need access to certificates and/or private keys stored in the Windows `Local Computer` certificate store from a Java program, you are out of luck.

## Solution
This software uses the Microsoft Detours[³][detours] library to intercept `CertOpenSystemStore` function calls and instead returns a handle to a collection type certificate store that aggregates both the `Current User` and `Local Computer` certificate stores.
In addition, it intercepts calls to `CryptAcquireContext` and adds `CRYPT_MACHINE_KEYSET` to `dwFlags` if the original call fails with an `NTE_BAD_KEYSET` ("Keyset does not exist") error. This is required to use keys that are stored in the `Local Computer` certificate store.

## Get
Download prebuild binaries [in the release section of this repo](https://github.com/oddbjornkvalsund/wcsa/releases) or clone this repo and build with `nmake` (requires a working Win32 build environment).

## Usage
Instead of starting your application with `java -jar myapp.jar`, you bootstrap it with the Windows Detours³ `withdll` utility: `withdll.exe /d:wcsa.dll java -jar myapp.jar`

Note that you might need to explicitly grant certificate key read permissions to the Windows user that runs the process.

# Limitations
* The returned collection certificate store is read-only, so adding, updating or removing certificates/private keys will fail.
* This software intercepts *all* calls to `CertOpenSystemStore`, so make sure this is what you really want before proceeding to use this in production.

# Licence
MIT Open Source Licence.

## References
1) [SunMSCAPI][mscapi]
2) [WinCrypt remarks][wincrypt]
3) [Microsoft Detours][detours]
4) [JDK-6782021][jdkbug]

[mscapi]: https://docs.oracle.com/javase/8/docs/technotes/guides/security/SunProviders.html#SunMSCAPI
[wincrypt]: https://docs.microsoft.com/en-us/windows/desktop/api/wincrypt/nf-wincrypt-certopensystemstorea#remarks
[detours]: https://github.com/Microsoft/Detours
[jdkbug]: https://bugs.openjdk.org/browse/JDK-6782021
