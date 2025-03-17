## Event ID 2 {#event-id-2}

- Event Log: Application
- Event Source: TameMyCerts
- Event Type: Error
- Required certification authority LogLevel: 2 (CERTLOG_ERROR)

### Event Sample

```
Error initializing Windows Default policy module:
{0}
```

- Placeholder {0} will contain the error message.

### Event Description

Occurs if the Windows Default policy was **not** successfully loaded during CA service startup. **Will cause the CA service to not start.**
