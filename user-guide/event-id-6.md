## Event ID 6 {#event-id-6}

- Event Log: Application
- Event Source: TameMyCerts
- Event Type: Warning
- Required certification authority LogLevel: 3 (CERTLOG_WARNING)

### Event Sample

```
Request {0} for {1} was denied because:
{2}
```

- Placeholder {0} will contain the Request ID number.
- Placeholder {1} will contain the certificate template name.
- Placeholder {2} will contain one or more reasons why the certificate request was denied.

![Preventing the ESC6 attack with TameMyCerts](resources/prevent-esc6.png)

### Event Description

Occurs if a certificate request was denied because of a policy violation. The event description contains detailed information which kind of policy violation caused the request to get denied.

Note that TameMyCerts can also detect abuse of (insecure flags)[#deny-insecure-flags] set on the certification authority, which can help prevent (compromise)[#uc-esc6] of the Active Directory environment. Occurrences are logged under this event ID.