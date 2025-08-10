## Modifying the Subject Distinguished Name of issued certificates {#modify-subject-dn}

> Applies to **online** and **offline** certificate templates.

TamyMyCerts allows modifying the Subject Distinguished Name (Subject DN) of a certificate before it gets issued. It is capable of retrieving properties from a mapped Active Directory object and put these values into the Subject Distinguished Name of a certificate. The resulting value can be either an attribute of a mapped Active Directory object, a field of the originating certificate request, a static value, or a combination of all.

![Populating the Subject Distinguished Name based on advanced rules with TameMyCerts](resources/subject-from-ad.png)

This is useful in the following scenarios:

- Certificates issued via Autoenrollment shall have another value as the `cn` Attribute for the `commonName` field (which would be the only combination with the original Microsoft policy module).
- Issued certificates shall contain additional Relative Distinguished Names that have not been requested by the enrollee.
- Issued certificates shall contain identities in form of a specific syntax which goes beyond built-in capabilities.
- A value from one certificate field shall be transferred to another one before issuing the certificate.

### Configuring

You define a `OutboundSubject` directive containing one or more `OutboundSubjectRule` rules.

The _OutboundSubjectRule_ directive can be configured as follows:

|Parameter|Mandatory|Description|
|---|---|---|
|`Field`|yes|The Relative Distinguished Name that shall be populated.|
|`Value`|yes|The value that shall be put into the configured certificate field. Can contain variables.|
|`Mandatory`|no|Specified if the configured value may be omitted if one of the variables is invalid or empty. If set to "true", requests will get denied in such a case. Defaults to `false`.|
|`Force`|no|Specifies how to act when the originating certificate request already contains a field of the specified type. If set to true and a field of same type is present, it **gets overwritten with the configured value**. If set to false, no action is made. Defaults to `false`.|

You may specify the following Relative Distinguished Names (RDN) for the "Field" directive:

|RDN|Maximum length|Typical AD attributes|Remarks|
|---|---|---|---|
|`emailAddress`|128|[mail](https://learn.microsoft.com/en-us/windows/win32/adschema/a-mail)||
|`commonName`|64|[name](https://learn.microsoft.com/en-us/windows/win32/adschema/a-name), [sAMAccountName](https://learn.microsoft.com/en-us/windows/win32/adschema/a-sAMAccountName), [displayName](https://learn.microsoft.com/en-us/windows/win32/adschema/a-displayName), [userPrincipalName](https://learn.microsoft.com/en-us/windows/win32/adschema/a-userPrincipalName)||
|`organizationName`|64|[company](https://learn.microsoft.com/en-us/windows/win32/adschema/a-company)||
|`organizationalUnitName`|64|[department](https://learn.microsoft.com/en-us/windows/win32/adschema/a-department)||
|`localityName`|128|[l](https://learn.microsoft.com/en-us/windows/win32/adschema/a-l)||
|`stateOrProvinceName`|128|[st](https://learn.microsoft.com/en-us/windows/win32/adschema/a-st)||
|`countryName`|2|[c](https://learn.microsoft.com/en-us/windows/win32/adschema/a-c)||
|`title`|64|[title](https://learn.microsoft.com/en-us/windows/win32/adschema/a-title)|not enabled by default|
|`givenName`|16|[givenName](https://learn.microsoft.com/en-us/windows/win32/adschema/a-givenName)|not enabled by default|
|`initials`|5|[initials](https://learn.microsoft.com/en-us/windows/win32/adschema/a-initials)|not enabled by default|
|`surname`|40|[sn](https://learn.microsoft.com/en-us/windows/win32/adschema/a-sn)|not enabled by default|
|`streetAddress`|30|[streetAddress](https://learn.microsoft.com/en-us/windows/win32/adschema/a-streetAddress)|not enabled by default|
|`unstructuredName`|1024|n/a||
|`unstructuredAddress`|1024|n/a||
|`serialNumber`|1024|n/a||

> The field names are processed _case-sensitive_.

The `Value` may contain a static string, or can be combined with attributes of mapped Active Directory objects, or content from the certificate request.

> It is also possible to remove a requested relative distinguished name from an issued certificate by setting the `Value` to an empty string.

You configure variables with the following syntax: `{Modifier:PropertyNameGoesHere}`

The following modifiers are currently supported:

|Modifier|Description|
|---|---|
|`ad`|Attributes of mapped Active Directory objects. For a list of supported Active Directory attributes, consult the [DirectoryServicesAttribute](#ds-attribute) section within the [Technical Reference](#tech-reference) chapter of this document.|
|`sdn`|Fields from the Subject Distinguished Name of the certificate request.|
|`san`|Fields from the Subject Alternative Name of the certificate request.|
|`yk`|Fields from [YubiKey PIV Attestation](#yubikey-piv-attestation) of the certificate request.|

> Note that if you plan to insert attributes from mapped Active Directory objects, you need to configure [DirectoryServicesMapping](#ds-mapping).

> Note that if you plan to inser attributes from a YubiKey, you need to configure [YubiKey PIV attestation](#yubikey-piv-attestation).

### Remarks

- Configuring an invalid `Field` will lead to certificate requests getting denied.
- Configuring a `Value` that violates length constraints for the selected `Field` will lead to certificate requests getting denied.
- It is possible to remove a relative distinguished name by setting the `Value` to an empty string. A more advanced variant of this is to transfer a value from one requested RDN to another one and then remove the original one.

### Examples

Issued certificates will have a `commonName` field which will contain the content of the `userPrincipalName` Active Directoy attribute of the mapped object. Furthermore, the `emailAddress` field will be populated with the content of the `mail` AD attribute. Should the `userPrincipalName` AD attribute not be populated in AD, the request will get denied. Should the `mail` AD attribute not be populated in AD, the certificate will get issued but not include an `emailAddress` field.

```xml
<DirectoryServicesMapping />
<OutboundSubject>
  <OutboundSubjectRule>
    <Field>commonName</Field>
    <Value>{ad:userPrincipalName}</Value>
    <Mandatory>true</Mandatory>
    <Force>true</Force>
  </OutboundSubjectRule>
  <OutboundSubjectRule>
    <Field>emailAddress</Field>
    <Value>{ad:mail}</Value>
  </OutboundSubjectRule>
</OutboundSubject>
```

The `commonName` will be built out of the two Active Directory attributes `sn` (surname) and `givenName`. Assuming the given name is "John" and the surname is "Doe", the `commonName` in the issued certificate will be "Doe, John".

```xml
<DirectoryServicesMapping />
<OutboundSubject>
  <OutboundSubjectRule>
    <Field>commonName</Field>
    <Value>{ad:sn}, {ad:givenName}</Value>
    <Mandatory>true</Mandatory>
    <Force>true</Force>
  </OutboundSubjectRule>
</OutboundSubject>
```

The `commonName` will be built out of the `name` Active Directory attribute and a static string. Assuming the `name` attribute contains "John Doe", the `commonName` in the issued certificate will be "John Doe is an awesome fellow!".

```xml
<DirectoryServicesMapping />
<OutboundSubject>
  <OutboundSubjectRule>
    <Field>commonName</Field>
    <Value>{ad:name} is an awesome fellow!</Value>
    <Mandatory>true</Mandatory>
    <Force>true</Force>
  </OutboundSubjectRule>
</OutboundSubject>
```

The `commonName` will be built out of the `displayName` Active Directory attribute. The `organizationName` will be set to "TameMyCerts", regardless if the originating certificate request did contain this field or not.

```xml
<OutboundSubject>
  <OutboundSubjectRule>
    <Field>commonName</Field>
    <Value>{ad:displayName}</Value>
    <Mandatory>true</Mandatory>
    <Force>true</Force>
  </OutboundSubjectRule>
  <OutboundSubjectRule>
    <Field>organizationName</Field>
    <Value>TameMyCerts</Value>
    <Force>true</Force>
  </OutboundSubjectRule>
</OutboundSubject>
```

Transfering the **first** `dNSName` of the Subject Alternative Name into the `commonName` field of the issued certificate.

```xml
<!-- does not require DirectoryServicesMapping -->
<OutboundSubject>
  <OutboundSubjectRule>
    <Field>commonName</Field>
    <Value>{san:dNSName}</Value>
    <Mandatory>true</Mandatory>
    <Force>true</Force>
  </OutboundSubjectRule>
</OutboundSubject>
```

The content of the `stateOrProvinceName` field will be removed from the issueed certificate, if present in the certificate request.

```xml
<OutboundSubject>
  <OutboundSubjectRule>
    <Field>stateOrProvinceName</Field>
    <Value></Value>
    <Mandatory>true</Mandatory>
    <Force>true</Force>
  </OutboundSubjectRule>
</OutboundSubject>
```

The content of the `stateOrProvinceName` field will be transferred from the certificate request into the `serialNumber` field of the issued certificate, and the `stateOrProvinceName` field will be removed from the issued certificate.

```xml
<OutboundSubject>
  <OutboundSubjectRule>
    <Field>stateOrProvinceName</Field>
    <Value></Value>
    <Mandatory>true</Mandatory>
    <Force>true</Force>
  </OutboundSubjectRule>
  <OutboundSubjectRule>
    <Field>serialNumber</Field>
    <Value>{sdn:stateOrProvinceName}</Value>
    <Mandatory>true</Mandatory>
    <Force>true</Force>
  </OutboundSubjectRule>
</OutboundSubject>
```
