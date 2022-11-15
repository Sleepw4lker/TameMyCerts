@echo off

:: Copyright 2021 Uwe Gradenegger <uwe@gradenegger.eu>

:: Licensed under the Apache License, Version 2.0 (the "License");
:: you may not use this file except in compliance with the License.
:: You may obtain a copy of the License at

:: http://www.apache.org/licenses/LICENSE-2.0

:: Unless required by applicable law or agreed to in writing, software
:: distributed under the License is distributed on an "AS IS" BASIS,
:: WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
:: See the License for the specific language governing permissions and
:: limitations under the License.

rmdir bin\Release /S /Q
mkdir bin\Release
mkdir bin\Release\examples
mkdir bin\Release\user-guide

MSBuild.exe ^
TameMyCerts.csproj ^
-property:Configuration=release  ^
/p:DebugSymbols=false ^
/p:DebugType=None ^
/p:CustomAfterMicrosoftCommonTargets="%VSINSTALLDIR%\MSBuild\Microsoft\VisualStudio\v%VisualStudioVersion%\TextTemplating\Microsoft.TextTemplating.targets" ^
/p:TransformOnBuild=true ^
/p:TransformOutOfDateOnly=false

copy install.ps1 bin\Release\
copy ..\CHANGELOG.adoc bin\Release\
copy ..\README.adoc bin\Release\
copy ..\LICENSE bin\Release\
copy ..\NOTICE bin\Release\
copy ..\examples\*.xml bin\Release\examples\
copy ..\user-guide\*.adoc bin\Release\user-guide\