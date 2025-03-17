## Global settings {#global-settings}

TameMyCerts supports the following flags to modify global (affecting request processing regardless of template configuration) behavior.

|Flag|Numerical value|Description|
|---|---|---|
|TMC_DENY_IF_NO_POLICY|0x1|Denies certificate request in case there is no policy configuration defined. Note that this causes the certification authority to globally deny all certificate requests by default until a policy configuration has been defined the published certificate templates ("failure-close" configuration).|
|TMC_WARN_ONLY_ON_INSECURE_FLAGS|0x2|Causes the policy module to not deny a certificate request when it contains the "san" request attribute and the **EDITF\_ATTRIBUTESUBJECTALTNAME2** flag has been enabled on the certification authority. Refer to section [Denying certificate requests for insecure combinations](#deny-insecure-flags) for more information. **It is recommended to not enable this flag.**|
|TMC_RESOLVE_NESTED_GROUP_MEMBERSHIPS|0x4|Instructs [Directory Services Mapping](#ds-mapping) to resolve nested Group Memberships using the use the **msds-TokenGroupNames** (<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1d810083-9741-4b0a-999b-30d9f2bc1f95>) Active Directory Attribute.|

> Flags can be combined with each other.

### Configuring

To **enable** a flag, enter the following commands into an elevated ("run as Administrator") command prompt (the example uses the TMC_DENY_IF_NO_POLICY flag, adjust to your needs):

```
certutil -setreg Policy\TmcFlags +0x1
```

To **disable** a flag, enter the following commands into an elevated ("run as Administrator") command prompt (the example uses the TMC_DENY_IF_NO_POLICY flag, adjust to your needs):

```
certutil -setreg Policy\TmcFlags -0x1
```

> As registry settings are applied on service startup, the certification authority service must be restarted for the settings to apply after a change.

```
net stop certsvc
net start certsvc
```