@echo off
cd %~dp0

echo Deleting existing PlgX folder
rmdir /s /q PlgX

echo Creating PlgX folder
mkdir PlgX

echo Copying files
xcopy KPUrl PlgX /s /e /exclude:PlgXExclude.txt

echo Compiling PlgX
..\KeePass.exe /plgx-create "%~dp0PlgX"

rem echo Releasing PlgX
rem move /y PlgX.plgx "Releases\Build Outputs\KPUrl.plgx"

echo Cleaning up
rmdir /s /q PlgX
