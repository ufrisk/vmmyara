vmmyara:
===============================
This is an API wrapper project that builds a vmmyara.dll/so that makes it easy
to use the Yara API from within a C/C++ application. The main purpose of this
project is to make it easy to use Yara from within the MemProcFS project.



Building Windows:
=================

1. git clone vmmyara: `git clone --recurse-submodules https://github.com/ufrisk/vmmyara`
2. Open the YARA solution at: ./yara/windows/vs2019/yara.sln
3. Upgrade to VS2022 and latest platform toolset when asked on first open.
4. Build release x64 (or x86).
5. On a successful build close the YARA solution.
6. Open the vmmyara solution at: ./vmmyara.sln
7. Build release x64 (or x86).
8. On a successful build close the vmmyara solution.
9. The resulting file vmmyara.dll will be in bin/x64/ (or bin/x86/).

Complete the above build flow once for each architecture. It's not possible to
first build YARA for both 32-bit and 64-bit and then build vmmyara.



Building Linux:
===============
1. Install dependencies. `sudo apt-get install automake libtool make gcc pkg-config flex bison libssl-dev libtool-bin`
2. git clone vmmyara: `git clone --recurse-submodules https://github.com/ufrisk/vmmyara`
3. cd into the yara directory relative to the vmmyara root - i.e. `cd yara`.
4. `./bootstrap.sh`
5. `./configure --with-crypto CFLAGS="-fPIC"`
6. `make`
7. cd into the vmmyara project directory relative to the vmmyara root, i.e. `cd vmmyara`
8. `make`
9. The resulting file vmmyara.so will be in the bin folder.


Building macOS:
===============
1. Install dependencies. `brew install openssl automake libtool pkg-config flex bison`
2. git clone vmmyara: `git clone --recurse-submodules https://github.com/ufrisk/vmmyara`
3. cd into the yara directory relative to the vmmyara root - i.e. `cd yara`.
4. `./bootstrap.sh`
5. `./configure --with-crypto CFLAGS="-fPIC -mmacosx-version-min=11.0" LDFLAGS="-mmacosx-version-min=11.0"`
6. `make`
7. cd into the vmmyara project directory relative to the vmmyara root, i.e. `cd vmmyara`
8. build using `make -f Makefile.macos` (for dynamic openssl import) or `make -f Makefile.macos2` (for static openssl include).
9. The resulting file vmmyara.dylib will be in the bin folder. Optionally code sign it.



Code Signing:
=============
The Windows and Linux releases are unsigned. Reason for this is that I don't maintain the project
and I don't sign other peoples code with my code signing certificate.
It's really a shame that the YARA project don't provide official DLLs.
