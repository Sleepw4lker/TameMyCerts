## Event ID 10 {#event-id-10}

- Event Log: Application
- Event Source: TameMyCerts
- Event Type: Error
- Required certification authority LogLevel: 2 (CERTLOG_ERROR)

### Event Sample

```
Request {0} will get denied. Unable to interpret policy for {1} because:
{2}
```

```
No certificate template information for request {0} could be retrieved from the certification authority service. The request will get denied.
```

```
No certificate template information for request {0} could be retrieved from the local certificate template cache. The request will get denied.
```

- Placeholder {0} will contain the Request ID number.
- Placeholder {1} will contain the certificate template name.
- Placeholder {2} will contain any additional error messages.

### Event Description

Occurs if a certificate request was denied because because the policy file for the certificate template could not be interpreted.
