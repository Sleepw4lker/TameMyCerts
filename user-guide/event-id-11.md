## Event ID 11 {#event-id-11}

- Event Log: Application
- Event Source: TameMyCerts
- Event Type: Information
- Required certification authority LogLevel: 4 (CERTLOG_VERBOSE)

### Event Sample

```
Request {0} was denied by the Windows Default policy module.
```

- Placeholder {0} will contain the Request ID number.

### Event Description

Occurs if the Windows Default policy module denied a certificate request, thus the additional logic of TameMyCerts was not triggered at all for the given request. As this is a normal occurrence during PKI operations, this event is just informational.
