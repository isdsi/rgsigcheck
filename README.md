# rgsigcheck
It checks the signature of win32 dll/exe and .net dll/exe is 32bit or 64bit

# build
I build this in Microsoft Visual Studio 2022.

# run
cmd > rgsicheck.exe
usage : rgsigcheck c:\windows\notepad.exe

cmd > rgsigcheck c:\windows\notepad.exe
this is not runnable. GetLastError() = 193
Image File Machine: x64
Press any key to stop...
