@echo off

set PRODUCT=TameMyCerts

"%SYSTEMROOT%\Microsoft.NET\Framework\v4.0.30319\ilasm.exe" ^
/DLL %PRODUCT%\CERTCLILIB.il ^
/res:%PRODUCT%\CERTCLILIB.res ^
/out=%PRODUCT%\CERTCLILIB.dll

"%SYSTEMROOT%\Microsoft.NET\Framework\v4.0.30319\ilasm.exe" ^
/DLL %PRODUCT%\CERTPOLICYLIB.il ^
/res:%PRODUCT%\CERTPOLICYLIB.res ^
/out=%PRODUCT%\CERTPOLICYLIB.dll