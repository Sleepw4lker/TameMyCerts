## Configuring per-template CDP, AIA or OCSP URIs {#cdp-aia-ocsp}

> Applies to **online** and **offline** certificate templates.

TameMyCerts allows to create custom certificate extensions for Certificate Revocation List Distribution Points (CDP), Authority Information Access (AIA) and Online Certificate Status Protocol (OCSP) on a per-template basis.

The directives are:

- CrlDistributionPoints
- AuthorityInformationAccess
- OnlineCertificateStatusProtocol

Each of those can contain one or more uniform resource identifiers (URIs). TameMyCerts supports the same token variables as the original Microsoft product (<https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc737264(v=ws.10)>), namely:

|Microsoft Token name |Description | Variable |
|---|---|---|
|`ServerDNSName`|The DNS name of the CA server |`%1`|
|`ServerShortName`|The NetBIOS name of the CA server|`%2`|
|`CaName`|The name of the CA |`%3`|
|`Cert_Suffix`|The renewal extension of the CA|`%4`|
|`ConfigurationContainer`|The location of the configuration container in Active Directory|`%6`|
|`CATruncatedName`|The "sanitized" name of the CA, 32 characters with a hash on the end|`%7`|
|`CRLNameSuffix`|The renewal extension for the CRL|`%8`|
|`CDPObjectClass`||`%10`|
|`CAObjectClass`||`%11`|

> Online Certificate Status Protocol (OCSP) URIs should only be configured in combination with Authority Information Access (AIA) URIs as they get written into the same certificate extension.

### Examples

Issuing CRL Distribution Point (CDP) URIs on a per-template basis:

```xml
<CrlDistributionPoints>
  <string>http://%1/CertData/%3%8%9.crl</string>
  <string>ldap:///CN=%7%8,CN=%3,CN=cdp,CN=Public Key Services,CN=Services,%6%10</string>
</CrlDistributionPoints>
```

Issuing Authority Information Access (AIA) URIs on a per-template basis:

```xml
<AuthorityInformationAccess>
  <string>http://%1/CertData/%3%4.crt</string>
  <string>ldap:///CN=%7,CN=AIA,CN=Public Key Services,CN=Services,%6%11</string>
</AuthorityInformationAccess>
```

Issuing Online Certificate Status Protocol (OCSP) URIs on a per-template basis:

```xml
<OnlineCertificateStatusProtocol>
  <string>http://ocsp.tamemycerts.com/ocsp</string>
</OnlineCertificateStatusProtocol>
```
