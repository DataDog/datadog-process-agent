set "RI_DEVKIT=C:\tools\msys64"
set "MSYSTEM=MINGW64"
set "PKG_CONFIG_PATH=/mingw64/lib/pkgconfig:/mingw64/share/pkgconfig"
set "ACLOCAL_PATH=/mingw64/share/aclocal:/usr/share/aclocal"
set "MANPATH=/mingw64/share/man"
set "MINGW_PACKAGE_PREFIX=mingw-w64-x86_64"
set "LANG=en_US.UTF-8"
set "PATH=c:\tools\msys64\mingw64\bin;c:\tools\msys64\usr\bin;%PATH%"
set "VCINSTALLDIR=C:\\Program Files (x86)\\Microsoft Visual Studio\\2017\\Community"
echo %CD%
call rake deps windres=true --trace
if %errorlevel% neq 0 exit /b %errorlevel%
call rake derive windres=true --trace
if %errorlevel% neq 0 exit /b %errorlevel%
call rake test windres=true --trace
if %errorlevel% neq 0 exit /b %errorlevel%
call rake build windres=true --trace
if %errorlevel% neq 0 exit /b %errorlevel%
