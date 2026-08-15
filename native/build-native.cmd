@echo off
setlocal
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
  echo Visual Studio Build Tools not found.
  exit /b 1
)
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSROOT=%%i"
if not defined VSROOT (
  echo MSVC x86/x64 tools not found.
  exit /b 1
)
call "%VSROOT%\VC\Auxiliary\Build\vcvarsall.bat" x86 10.0.19041.0 -vcvars_ver=14.16 >nul
if errorlevel 1 exit /b %errorlevel%

if not exist build mkdir build
rc.exe /nologo /c65001 /d UNICODE /d _UNICODE /fo build\UpdateLock.res UpdateLock.rc
if errorlevel 1 exit /b %errorlevel%

cl.exe /nologo /std:c++17 /utf-8 /O2 /MT /EHsc /GS /guard:cf /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN /DNOMINMAX /D_WIN32_WINNT=0x0601 /DWINVER=0x0601 /W4 /WX /c UpdateLock.cpp /Fo:build\UpdateLock.obj
if errorlevel 1 exit /b %errorlevel%

link.exe /nologo /out:build\UpdateLock.exe /subsystem:windows,6.01 /machine:x86 /dynamicbase /nxcompat /guard:cf /opt:ref /opt:icf build\UpdateLock.obj build\UpdateLock.res advapi32.lib crypt32.lib ole32.lib shell32.lib user32.lib gdi32.lib comctl32.lib version.lib
if errorlevel 1 exit /b %errorlevel%

cl.exe /nologo /std:c++17 /utf-8 /O2 /MT /EHsc /GS /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN /DNOMINMAX /D_WIN32_WINNT=0x0601 /DWINVER=0x0601 /W4 /WX NativeTests.cpp /Fe:build\NativeTests.exe /link /subsystem:console,6.01 /machine:x86 advapi32.lib crypt32.lib ole32.lib shell32.lib user32.lib gdi32.lib comctl32.lib version.lib
exit /b %errorlevel%
