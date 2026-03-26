@echo off
mkdir builds 2>nul

echo Building windows-amd64...
set GOOS=windows
set GOARCH=amd64
go build -o builds\awgconfbot-windows-amd64.exe .
if errorlevel 1 goto :fail

echo Building linux-amd64...
set GOOS=linux
set GOARCH=amd64
go build -o builds\awgconfbot-linux-amd64 .
if errorlevel 1 goto :fail

echo Building linux-arm64...
set GOOS=linux
set GOARCH=arm64
go build -o builds\awgconfbot-linux-arm64 .
if errorlevel 1 goto :fail

echo Building linux-arm...
set GOOS=linux
set GOARCH=arm
set GOARM=7
go build -o builds\awgconfbot-linux-armv7 .
if errorlevel 1 goto :fail

echo Done! All builds completed.
exit /b 0

:fail
echo Build failed!
exit /b 1
