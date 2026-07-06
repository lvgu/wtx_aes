@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cl /EHsc /MD main.cpp /link /OUT:my_aes.exe advapi32.lib
pause