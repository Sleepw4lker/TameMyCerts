## Adding custom certificate extensions {#custom-extensions}

TameMyCerts allows to add custom certificate extensions with **static** values.

> Custom certificate extensions are not marked as mandatory.

|Field|Mandatory|Description|
|---|---|---|
|Oid|**yes**|The Object Identifier of the extension.|
|Value|**yes**|The BASE64-encoded value of the extension.|

Examples for this might be:

|Extension|Object Identifier|Value|
|---|---|---|
|OCSP must-staple|1.3.6.1.5.5.7.1.24|`MAMCAQU=`|
|OCSP NoCheck|1.3.6.1.5.5.7.48.1.5|no value|
|Microsoft Hyper-V / SCVMM Virtual Machine Connection|1.3.6.1.4.1.311.62.1.1.1|`AgEE`|

### Examples

Adding the OCSP must-staple certificate extension to an issued certificate.

```xml
<CustomCertificateExtensions>
    <CustomCertificateExtension>
        <Oid>1.3.6.1.5.5.7.1.24</Oid>
        <Value>MAMCAQU=</Value>
    </CustomCertificateExtension>
</CustomCertificateExtensions>
```

Adding the OCSP NoCheck certificate extension to an issued certificate.

```xml
<CustomCertificateExtensions>
    <CustomCertificateExtension>
        <Oid>1.3.6.1.5.5.7.48.1.5</Oid>
    </CustomCertificateExtension>
</CustomCertificateExtensions>
```

Adding the Hyper-V / SCVMM Virtual Machine Connection certificate extension to an issued certificate.

```xml
<CustomCertificateExtensions>
    <CustomCertificateExtension>
        <Oid>1.3.6.1.4.1.311.62.1.1.1</Oid>
        <Value>AgEE</Value>
    </CustomCertificateExtension>
</CustomCertificateExtensions>
```
