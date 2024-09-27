## Global settings {#global-settings}

TameMyCerts 

|Flag|Numerical value|Description|
|---|---|---|
|TMC_DENY_IF_NO_POLICY|0x1|Denies certificate request in case there is no policy configuration defined. Note that this causes the certification authority to globally deny all certificate requests by default until a policy configuration has been defined the published certificate templates.|
|TMC_WARN_ONLY_ON_INSECURE_FLAGS|0x2|Causes the policy module to not deny a certificate request when it contains the "san" request attribute and the **EDITF\_ATTRIBUTESUBJECTALTNAME2** flag has been enabled on the certification authority. Refer to section [Denying certificate requests for insecure combinations](#deny-insecure-flags) for more information. **It is recommended to not enable this flag.**|
|TMC_DEEP_LDAP_SEARCH|0x4|not yet implemented|

> Flags can be combined with each other.

### Configuring

To **enable** a flag, enter the following commands into an elevated ("run as Administrator") command prompt (the example uses the TMC_DENY_IF_NO_POLICY flasg, adjust to your needs):

```
certutil -setreg Policy\TmcFlags +0x1
```

To **disable** a flag, enter the following commands into an elevated ("run as Administrator") command prompt (the example uses the TMC_DENY_IF_NO_POLICY flasg, adjust to your needs):

```
certutil -setreg Policy\TmcFlags -0x1
```

> As registry settings are applied on service startup, the certification authority service must be restarted for the settings to apply after a change.

```
net stop certsvc
net start certsvc
```