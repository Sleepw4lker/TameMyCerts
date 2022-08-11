:: Call this from the Visual Studio Developer CMD

:: Builds against the debug configuration

@echo off

rmdir bin\Debug /S /Q
mkdir bin\Debug
mkdir bin\Debug\examples

MSBuild.exe ^
TameMyCerts.csproj ^
-property:Configuration=debug

copy install.ps1 bin\Debug\
copy Sample_*.xml bin\Debug\examples\