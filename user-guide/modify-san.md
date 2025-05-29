## Modifying the Subject Alternative Name of issued certificates {#modify-san}

> Applies to **online** and **offline** certificate templates.

TamyMyCerts allows modifying the Subject Alternative Name (SAN) of a certificate before it gets issued. It is capable of retrieving properties from a mapped Active Directory object and put these values into the SAN of a certificate. The resulting value can be either an attribute of a mapped AD object, a field of the originating certificate request, a static value, or a combination of all.

### Configuring

You define a `OutboundSubjectAlternativeName` directive containing `OutboundSubjectRule` rules.

The `OutboundSubjectRule` directive can be configured as follows:

|Parameter|Mandatory|Description|
|---|---|---|
|`Field`|yes|The Relative Distinguished Name that shall be populated.|
|`Value`|yes|The value that shall be put into the configured certificate field. Can contain variables.|
|`Mandatory`|no|Specified if the configured value may be omitted if one of the variables is invalid or empty. If set to "true", requests will get denied in such a case. Defaults to `false`.|
|`Force`|no|Specifies how to act when the originating certificate request already contains a field of the specified type. If set to true and a field of same type is present, **an additional entry with the configured value gets added to the SAN**. If set to `false`, no action is performed. Defaults to `false`.|

You may specify the following Subject Alternative Name types for the "Field" directive:

- `dnsName`
- `rfc822Name`
- `uniformResourceIdentifier`
- `userPrincipalName`
- `ipAddress`

> The field names are processed _case-sensitive_.

The `Value` may contain a static string, or can be combined with attributes of mapped Active Directory objects, or content from the certificate request.

You configure variables with the following syntax: `{Modifier:PropertyNameGoesHere}`

The following modifiers are currently supported:

|Modifier|Description|
|---|---|
|`ad`|Attributes of mapped Active Directory objects. For a list of supported Active Directory attributes, consult the [DirectoryServicesAttribute](#ds-attribute) section within the [Technical Reference](#tech-reference) chapter of this document.|
|`sdn`|Fields from the Subject Distinguished Name of the certificate request.|
|`san`|Fields from the Subject Alternative Name of the certificate request.|

> Note that if you plan to insert attributes from mapped Active Directory objects, you need to configure [DirectoryServicesMapping](#ds-mapping).

### Examples

The SAN gets supplemented with a `dNSName` containing the `name` attribute of a computer object (so that the unqualified DNS name is part of the SAN) .

```xml
<DirectoryServicesMapping />
<OutboundSubjectAlternativeName>
  <OutboundSubjectRule>
    <Field>dNSName</Field>
    <Value>{ad:name}</Value>
    <Mandatory>true</Mandatory>
  </OutboundSubjectRule>
</OutboundSubjectAlternativeName>
```

The `commonName` from the Subject DN is transferred to the Subject Alternative Name (SAN) in form of a `dNSName`.

```xml
<!-- does not require DirectoryServicesMapping -->
<OutboundSubjectAlternativeName>
  <OutboundSubjectRule>
    <Field>dNSName</Field>
    <Value>{sdn:commonName}</Value>
    <Mandatory>true</Mandatory>
  </OutboundSubjectRule>
</OutboundSubjectAlternativeName>
```
