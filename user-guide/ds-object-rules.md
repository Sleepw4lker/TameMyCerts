## Configuring directory object rules {#ds-object-rules}

> Applies to **online** and **offline** certificate templates.
> Requires [Directory Services Mapping](#ds-mapping) to be enabled.

Directory services mapping can be configured to apply conditions that must match for attributes of a mapped directory object.

The configuration goes as follows:

|Parameter|Mandatory|Description|
|---|---|---|
|DirectoryServicesAttribute|**yes**|The attribute of the mapped object that shall be evaluated.|
|Mandatory|no|Specified if the attribute may be omitted if it is invalid or empty. If set to "true", requests will get denied in such a case.|
|Patterns|**yes**|You can define one or more "Pattern" directives describing expressions of which the _sAMAccountName_ attribute of the mapped AD object must match at least one of to get either permitted or denied.|

For a list of supported Active Directory attributes, consult the [DirectoryServicesAttribute](#ds-attribute) section within the [Technical Reference](#tech-reference) chapter of this document.

For instructions on how to configure the _Patterns_ directive, consult the [Pattern](#pattern) section within the [Technical Reference](#tech-reference) chapter of this document.

### Examples

```xml
<DirectoryServicesMapping>
  <!-- other directives have been removed for this example -->
  <DirectoryObjectRules>
    <DirectoryObjectRule>
      <DirectoryServicesAttribute>description</DirectoryServicesAttribute>
      <Mandatory>true</Mandatory>
      <Patterns>
        <Pattern>
          <Expression>^Admin$</Expression>
          <TreatAs>RegEx</TreatAs>
          <Action>Deny</Action>
        </Pattern>
      </Patterns>
    </DirectoryObjectRule>
  </DirectoryObjectRules>
</DirectoryServicesMapping>
```
