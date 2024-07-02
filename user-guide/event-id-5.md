## Event ID 5 {#event-id-5}

- Event Log: Application
- Event Source: TameMyCerts
- Event Type: Warning
- Required certification authority LogLevel: 0 (CERTLOG_MINIMAL)

### Event Sample

```
Audit mode is enabled for {1}. Request {0} would get denied because:
{2}
```

- Placeholder {0} will contain the Request ID number.
- Placeholder {1} will contain the certificate template name.
- Placeholder {2} will contain one or more reasons why the certificate request would get denied.

### Event Description

Occurs if [Audit only mode](#audit-only-mode) is enabled for a certificate template and a certificate request would get denied because of a policy violation. Contains a detailed information which kind of policy violation caused the request to get denied.