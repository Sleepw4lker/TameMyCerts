## Event ID 8 {#event-id-8}

- Event Log: Application
- Event Source: TameMyCerts
- Event Type: Warning
- Required certification authority LogLevel: 3 (CERTLOG_WARNING)

### Event Sample

```
Unable to find policy file for {0}. Request {1} will get denied.
```

- Placeholder {0} will contain the certificate template name.
- Placeholder {1} will contain the Request ID number.

### Event Description

Occurs if there is no policy configuration file defined for the certificate template used certificate request, and TameMyCerts global flags are configured to deny certificate requests when there is no policy defined. The certificate request gets denied in this case.
