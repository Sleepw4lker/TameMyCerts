## Permitting empty identities {#empty-identities}

> Applies to **online** and **offline** certificate templates.

For any certificate template that has a policy configuration defined, TameMyCerts will ensure that the resulting certificate will contain an identity, either in the Subject Distinguished Name or the Subject Alternative Name. If the resulting certificate would not contain an identity, the certificate request will get denied and an event will be [logged](#logs).

Should you have the requirement to issue such certificates regardless of not containing an identity, you may change the behavior with the _PermitEmptyIdentites_ directive:

```xml
<PermitEmptyIdentites>true</PermitEmptyIdentites>
```
