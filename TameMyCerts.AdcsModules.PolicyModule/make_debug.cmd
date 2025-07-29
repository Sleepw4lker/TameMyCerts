@echo off

rmdir bin\Debug /S /Q
mkdir bin\Debug

MSBuild.exe TameMyCerts.csproj -property:Configuration=debug

copy install.ps1 bin\Debug\net8.0-windows