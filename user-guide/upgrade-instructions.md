## Upgrade instructions

### Upgrading TameMyCerts to version 1.8

Beginning with Version 1.8, TameMyCerts uses .NET 10.0 instead of the previously used .NET 8.0. Therefore, you must [install](#prerequisites) the .NET 10.0 Desktop runtime prior to installing the module.

Uninstall the previous version first **with the installer that came with the old version**. Refer to [Uninstalling TameMyCerts](#uninstalling) for more detailed instructions. Afterwards, you can uninstall the old .NET runtime as well.

### Upgrading TameMyCerts to version 1.7

Beginning with Version 1.7, TameMyCerts uses .NET 8.0 instead of the previously used .NET Framework 4.7.2. Therefore, you must [install](#prerequisites) the .NET 8.0 Desktop runtime prior to installing the module.

Policy configuration files are now strictly processed, means that there will be errors raised when they contain invalid nodes. This may especially affect the following:

- If policy configuration files still contain `KeyAlgorithm` nodes (which were removed with version 1.6), these must be removed from the configuration files.
- The `Action` directives as well as the `TreatAs` directives for `Pattern` directives as processed case-sensitive, means that they must be specified exactly as documentated.

### Upgrading TameMyCerts to version 1.6

If you are upgrading from a TameMyCerts version older than 1.6, you must adjust some elements in your policy configuration files.

- Modifications of the Subject Distinguished Name has been moved out of the `DirectoryServicesMapping`. The directives have been renamed and the syntax has changed to enable advanced modifications of both Subject Distinguished Name (Subject DN) and Subject Alternative Name (SAN).
  
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

- `organizationalUnit` under `SubjectRule` must be changed to `organizationalUnitName`.

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

- `AllowedPattern` under `SubjectRule` must be changed to `Pattern` with differing syntax.
- `DisallowedPattern` under `SubjectRule` must be changed to `Pattern` with differing syntax.

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
