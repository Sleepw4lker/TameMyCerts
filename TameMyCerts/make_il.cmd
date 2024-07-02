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

set PRODUCT=TameMyCerts

"%SYSTEMROOT%\Microsoft.NET\Framework\v4.0.30319\ilasm.exe" ^
/DLL %PRODUCT%\CERTCLILIB.il ^
/res:%PRODUCT%\CERTCLILIB.res ^
/out=%PRODUCT%\CERTCLILIB.dll

"%SYSTEMROOT%\Microsoft.NET\Framework\v4.0.30319\ilasm.exe" ^
/DLL %PRODUCT%\CERTPOLICYLIB.il ^
/res:%PRODUCT%\CERTPOLICYLIB.res ^
/out=%PRODUCT%\CERTPOLICYLIB.dll