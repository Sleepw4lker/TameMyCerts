## Issuing Certificates with an exactly defined validity period {#startdate}

> Applies to **online** and **offline** certificate templates.
> Does not support [Audit only mode](#audit-only-mode).
> This feature is independent from certificate templates. It can only be enabled used globally on a certification authority level.

The Windows Default policy module allows to specify the exact expiration date (<https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/change-certificates-expiration-date>) (NotAfter) for a certificate by specifying an `ExpirationDate` attribute whilst submitting the certificate request. TameMyCerts adds support for a `StartDate` attribute which does the exact same for the begin of the certificates validity period (the "NotBefore" certificate property).

### Configuring

To enable the feature, you must enable the `EDITF_ATTRIBUTEENDDATE` flag for the policy module of the certification authority and restart the certification authority service afterwards.

```batch
certutil -setreg Policy\Editflags +EDITF_ATTRIBUTEENDDATE
net stop certsvc
net start certsvc
```

Now you can specify both `StartDate` and `ExpirationDate` request attribute in IETF RFC 2616 (<https://datatracker.ietf.org/doc/html/rfc2616>) compliant form whilst submitting the certificate request.

A syntax example for a compliant date form could be:

```batch
Tue, 1 Mar 2022 08:00:00 GMT
```

When an invalid date is being requested, the certificate request will get denied with [error code](#error-codes) `ERROR_INVALID_TIME`.

> TameMyCerts currently only supports specifying `StartDate` whilst submitting the certificate request but not as custom attributes within the certificate request itself. The alternative method of specifying `ValidityPeriod` and `ValidityPeriodUnits` for the expiration date can currently not be used in combination with the `StartDate` attribute as it gets applied afterwards and thus won’t deliver the expected result.

### Examples

Requesting a certificate that shall be valid from Mar 1, 2022 08:00 until Mar 1, 2022 16:00:

```batch
certreq.exe -config "caserver.tamemycerts.local\TameMyCerts CA" -attrib "CertificateTemplate:TameMyCertsWebServer\nStartDate:Tue, 1 Mar 2022 08:00:00 GMT\nExpirationDate:Tue, 1 Mar 2022 16:00:00 GMT" -submit "MyCertificateRequest.req"
```
