## Event ID 4 {#event-id-4}

- Event Log: Application
- Event Source: TameMyCerts
- Event Type: Error
- Required certification authority LogLevel: 2 (CERTLOG_ERROR)

### Event Sample

```
Shutting down Windows Default policy module failed:
{0}
```

- Placeholder {0} will contain the error message.

### Event Description

Occurs if the Windows Default policy was **not** successfully unloaded during CA service shutdown.