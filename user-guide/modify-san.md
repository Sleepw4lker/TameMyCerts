## Modifying the Subject Alternative Name of issued certificates {#modify-san}

> Applies to **online** and **offline** certificate templates.

TamyMyCerts allows modifying the Subject Alternative Name (SAN) of a certificate before it gets issued. It is capable of retrieving properties from a mapped Active Directory object and put these values into the SAN of a certificate. The resulting value can be either an attribute of a mapped AD object, a field of the originating certificate request, a static value, or a combination of all.

### Configuring

You define a **OutboundSubjectAlternativeName** directive containing **OutboundSubjectRule** rules. The syntax and logic for the "SubjectRule" is the exact same as for [Modifying the Subject Distinguished Name of issued certificates](#modify-subject-dn).

The _OutboundSubjectRule_ directive can be configured as follows:

|Parameter|Mandatory|Description|
|---|---|---|
|Field|yes|The Relative Distinguished Name that shall be populated.|
|Value|yes|The value that shall be put into the configured certificate field. Can contain variables.|
|Mandatory|no|Specified if the configured value may be omitted if one of the variables is invalid or empty. If set to "true", requests will get denied in such a case. Defaults to **false**.|
|Force|no|Specifies how to act when the originating certificate request already contains a field of the specified type. If set to true and a field of same type is present, **an additional entry with the configured value gets added to the SAN**. If set to false, no action is made. Defaults to **false**.|

You may specify the following Subject Alternative Name types for the "Field" directive:

-  dnsName

-  rfc822Name

-  uniformResourceIdentifier

-  userPrincipalName

-  ipAddress

> The field names are processed _case-sensitive_.

### Examples

The SAN gets supplemented with a _dNSName_ containing the _name_ attribute of a computer object (so that the unqualified DNS name is part of the SAN) .

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

The _commonName_ (given that it is a DNS name) from the Subject DN is transferred to the Subject Alternative Name (SAN) in form of a _dNSName_.

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