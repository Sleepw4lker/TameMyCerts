## Upgrade instructions

### Upgrading TameMyCerts to version 1.7

Beginning with Version 1.7, TameMyCerts uses .NET 8.0 instead of the previously used .NET Framewotk 4.7.2. Therefore, you must [install](#prerequisites) the .NET 8.0 Desktop runtime prior to installing the module.

### Upgrading TameMyCerts to version 1.6

If you are upgrading from a TameMyCerts version older than 1.6, you must adjust some elements in your policy configuration files.

- Modifications of the Subject Distinguished Name has been moved out of the _DirectoryServicesMapping_. The directives have been renamed and the syntax has changed to enable advanced modifications of both Subject Distinguished Name (Subject DN) and Subject Alternative Name (SAN).
  
TameMyCerts version 1.5 and lower used the following syntax:

```xml
<DirectoryServicesMapping>
  <!-- other directives have been left out for simplicity -->
  <SubjectDistinguishedName>
    <RelativeDistinguishedName>
      <Field>emailAddress</Field>
      <DirectoryServicesAttribute>mail</DirectoryServicesAttribute>
      <Mandatory>true</Mandatory>
    </RelativeDistinguishedName>
  </SubjectDistinguishedName>
</DirectoryServicesMapping>
```

TameMyCerts version 1.6 and newer now uses the following syntax:

```xml
<DirectoryServicesMapping>
  <!-- other directives have been left out for simplicity -->
</DirectoryServicesMapping>
<OutboundSubject>
  <OutboundSubjectRule>
    <Field>emailAddress</Field>
    <Value>{ad:mail}</Value>
    <Mandatory>true</Mandatory>
    <Force>true</Force>
  </OutboundSubjectRule>
</OutboundSubject>
```

### Upgrading TameMyCerts to version to 1.2 or newer

If you are upgrading from a TameMyCerts version older than 1.2, you must adjust some elements in your policy configuration files.

- **organizationalUnit** under _SubjectRule_ must be changed to **organizationalUnitName**.

TameMyCerts version 1.1 and lower used the following syntax:

```xml
<SubjectRule>
  <Field>organizationalUnit</Field>
  <!-- other directives have been left out for simplicity -->
</SubjectRule>
```

TameMyCerts version 1.2 now uses the following syntax:

```xml
<SubjectRule>
  <Field>organizationalUnitName</Field>
  <!-- other directives have been left out for simplicity -->
</SubjectRule>
```

### Upgrading TameMyCerts to version to 1.1 or newer

If you are upgrading from a TameMyCerts version older than 1.1, you must adjust some elements in your policy configuration files.

- **AllowedPattern** under _SubjectRule_ must be changed to **Pattern** with differing syntax.
- **DisallowedPattern** under _SubjectRule_ must be changed to **Pattern** with differing syntax.

TameMyCerts version 1.0 used the following syntax:

```xml
<SubjectRule>
  <Field>commonName</Field>
  <AllowedPatterns>
    <string>^[-_a-zA-Z0-9]*\.tamemycerts\.com$</string>
  </AllowedPatterns>
  <DisallowedPatterns>
    <string>^.*(porn|gambling).*$</string>
  </DisallowedPatterns>
</SubjectRule>
```

TameMyCerts version 1.1 now uses the following syntax:

```xml
<SubjectRule>
  <Field>commonName</Field>
  <Patterns>
    <Pattern>
      <Expression>^[-_a-zA-Z0-9]*\.tamemycerts\.com$</Expression>
    </Pattern>
    <Pattern>
      <Expression>^.*(porn|gambling).*$</Expression>
      <Action>Deny</Action>
    </Pattern>
  </Patterns>
</SubjectRule>
```