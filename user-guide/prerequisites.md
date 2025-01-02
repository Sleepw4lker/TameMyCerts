# Prerequisites {#prerequisites}

TameMyCerts is intended to be installed on a server with the Certification Authority role installed.

## Supported certification authority modes

The following modes for the certification authority role are supported by TameMyCerts:

|CA mode|Support status|
|---|---|
|Enterprise Root|supported|
|Enterprise Issuing|supported|
|Standalone Root|**not** supported|
|Standalone Issuing|**not** supported|

## Supported operating systems

The module was successfully tested and is supported with the following operating systems:

- Microsoft Windows Server vNext Insider Preview (Build 25977)

- Microsoft Windows Server 2022

- Microsoft Windows Server 2019

- Microsoft Windows Server 2016

Other Microsoft Windows Server operating systems may work but are not supported.

## Software prerequisites

For Windows Server 2016, Microsoft .NET Framework 4.7.2 (<https://support.microsoft.com/en-us/topic/microsoft-net-framework-4-7-2-offline-installer-for-windows-05a72734-2127-a15d-50cf-daf56d5faec2>) must be installed. Windows Server versions newer than Windows Server 2016 already fulfill this requirement.