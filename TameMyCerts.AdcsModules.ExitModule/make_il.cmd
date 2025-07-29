@echo off

"%SYSTEMROOT%\Microsoft.NET\Framework\v4.0.30319\ilasm.exe" /DLL CERTCLILIB.il /res:CERTCLILIB.res /out=CERTCLILIB.dll
"%SYSTEMROOT%\Microsoft.NET\Framework\v4.0.30319\ilasm.exe" /DLL CERTEXITLIB.il /res:CERTEXITLIB.res /out=CERTEXITLIB.dll