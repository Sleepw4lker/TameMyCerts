## Event ID 9 {#event-id-9}

- Event Log: Application
- Event Source: TameMyCerts
- Event Type: Error
- Required certification authority LogLevel: 2 (CERTLOG_ERROR)

### Event Sample

```
The {0} policy module currently does not support standalone certification authorities.
```

- Placeholder {0} will contain the policy module name.

### Event Description

Occurs it the TameMyCerts policy module is loaded on a standalone certification authority, which is unsupported at the moment. **Will cause the CA service to not start.**
