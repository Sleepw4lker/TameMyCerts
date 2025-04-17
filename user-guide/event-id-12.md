## Event ID 12 {#event-id-12}

- Event Log: Application
- Event Source: TameMyCerts
- Event Type: Information
- Required certification authority LogLevel: 4 (`CERTLOG_VERBOSE`)

### Event Sample

```
Request {0} for {1} will get issued.
```

- Placeholder `{0}` will contain the Request ID number.
- Placeholder `{1}` will contain the certificate template name.

### Event Description

This is an informational event containing the request ID and the certificate template name in case TameMyCerts decides that the certificate request shall get issued.
