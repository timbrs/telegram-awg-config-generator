@echo off
mkdir builds 2>nul

echo Building Windows amd64...
set GOOS=windows
set GOARCH=amd64
go build -o builds\awgconfbot.exe .
if errorlevel 1 goto :fail

echo Building Linux amd64...
set GOOS=linux
set GOARCH=amd64
go build -o builds\awgconfbot .
if errorlevel 1 goto :fail

echo Done!
exit /b 0

:fail
echo Build failed!
exit /b 1
