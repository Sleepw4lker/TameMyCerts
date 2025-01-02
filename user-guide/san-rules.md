## Configuring rules for Subject Alternative Names of a CSR {#san-rules}

> Applies only to **offline** certificate templates.

### Configuring

Rules for the Subject Alternative Name (SAN) get specified within a "SubjectRule" node under "SubjectAlternativeName" section. The syntax and logic for the "SubjectRule" is the exact same as for [Rules for the Subject Distinguished Name (Subject DN)](#subject-rules).

To define a policy for one or more subject alternative name (SAN) type, adjust the "field" to one of the following (as defined in IETF RFC 5280 (<https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6>).

- dNSName

- iPAddress

- rfc822Name

- uniformResourceIdentifier

- userPrincipalName

> Other SAN types are currently not supported. However, the ones that are supported should be sufficient for the majority of use cases.

Under certain circumstances, it is also possible to [supplement DNS Names and IP Addresses from the Subject Distinguished Name into the Subject Alternative Name extension](#supplement-dns-names).

### Examples

Incoming requests **may** contain exactly one _userPrincipalName_, but if present, it must be beneath the _tamemycerts.com_ Domain.

```xml
<SubjectAlternativeName>
  <SubjectRule>
    <Field>userPrincipalName</Field>
    <!-- other directives have been left out for simplicity -->
    <Patterns>
      <Pattern>
        <Expression>^[-_a-zA-Z0-9\.]*\@tamemycerts\.com$</Expression>
      </Pattern>
    </Patterns>
  </SubjectRule>
</SubjectAlternativeName>
```