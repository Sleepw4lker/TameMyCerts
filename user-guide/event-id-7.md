## Event ID 7 {#event-id-7}

- Event Log: Application
- Event Source: TameMyCerts
- Event Type: Warning
- Required certification authority LogLevel: 4 (CERTLOG_VERBOSE)

### Event Sample

```
Unable to find policy file for {0}. Request {1} will get issued.
```

- Placeholder {0} will contain the certificate template name.
- Placeholder {1} will contain the Request ID number.

### Event Description

Occurs if there is no policy configuration file defined for the certificate template used certificate request. The certificate request gets allowed in this case.
