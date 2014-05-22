@echo off
cd %~dp0

echo Deleting existing PlgX folder
rmdir /s /q PlgX
del /Q KPUrl.plgx

echo Creating PlgX folder
mkdir PlgX

echo Copying files
xcopy KPUrl PlgX /s /e /exclude:PlgXExclude.txt

echo Compiling PlgX
..\KeePass.exe --plgx-create "%~dp0KPUrl"  --plgx-prereq-kp:2.26 ----plgx-prereq-os:Windows

echo Cleaning up
rmdir /s /q PlgX
