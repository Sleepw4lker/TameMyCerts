:: Call this from the Visual Studio Developer CMD

:: Builds against the release configuration
:: Automatically increases version number

@echo off

rmdir bin\Release /S /Q
mkdir bin\Release

MSBuild.exe ^
TameMyCerts.csproj ^
-property:Configuration=release  ^
/p:DebugSymbols=false ^
/p:DebugType=None ^
/p:CustomAfterMicrosoftCommonTargets="%VSINSTALLDIR%\MSBuild\Microsoft\VisualStudio\v%VisualStudioVersion%\TextTemplating\Microsoft.TextTemplating.targets" ^
/p:TransformOnBuild=true ^
/p:TransformOutOfDateOnly=false

copy install.ps1 bin\Release\
copy Sample_*.xml bin\Debug\
copy ..\README.adoc bin\Release\
copy ..\LICENSE bin\Release\
copy ..\NOTICE bin\Release\