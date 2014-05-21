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
KPUrl\bin\Release\KeePass.exe /plgx-create "%~dp0KPUrl"

echo Cleaning up
rmdir /s /q PlgX
