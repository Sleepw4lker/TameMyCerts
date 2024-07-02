## Event ID 13 {#event-id-13}

- Event Log: Application
- Event Source: TameMyCerts
- Event Type: Information
- Required certification authority LogLevel: 4 (CERTLOG_VERBOSE)

### Event Sample

```
Request {0} for {1} will be put into pending state.
```

- Placeholder {0} will contain the Request ID number.
- Placeholder {1} will contain the certificate template name.

### Event Description

This is an informational event containing the request ID and the certificate template name in case TameMyCerts decides that the certificate request shall be put into pending state.