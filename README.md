vmmyara:
===============================
This is an API wrapper project that builds a vmmyara.dll/so that makes it easy
to use the Yara API from within a C/C++ application. The main purpose of this
project is to make it easy to use Yara from within the MemProcFS project.



Building Windows:
=================

1. Open the YARA solution at: ./yara/windows/vs2017/yara.sln
2. Upgrade to VS2022 and latest platform toolset when asked on first open.
3. Build release x64 (or x86).
4. On a successful build close the YARA solution.
5. Open the vmmyara solution at: ./vmmyara.sln
6. Build release x64 (or x86).
7. On a successful build close the vmmyara solution.
8. The resulting file vmmyara.dll will be in bin/x64/ (or bin/x86/).

Complete the above build flow once for each architecture. It's not possible to
first build YARA for both 32-bit and 64-bit and then build vmmyara.



Building Linux:
===============
1. Install dependencies. `sudo apt-get install automake libtool make gcc pkg-config flex bison libssl-dev libtool-bin`
2. cd into the yara directory relative to the vmmyara root - i.e. `cd yara`.
3. `./bootstrap.sh`
4. `./configure --with-crypto`
5. `make`
6. cd into the vmmyara project directory relative to the vmmyara root, i.e. `cd vmmyara`
7. `make`
8. The resulting files libyara.so and vmmyara.so will be in the bin folder.



Code Signing:
=============
The release is not signed. Reason for this is that I don't maintain the yara
project and I don't sign other peoples code with my code signing certificate.
It's really a shame that the YARA project don't provide official DLLs.
