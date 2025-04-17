## Event ID 14 {#event-id-14}

- Event Log: Application
- Event Source: TameMyCerts
- Event Type: Warning
- Required certification authority LogLevel: 3 (`CERTLOG_WARNING`)

### Event Sample

```
The following warnings have been logged during the processing of request {0} for {1}:
{2}
```

- Placeholder `{0}` will contain the Request ID number.
- Placeholder `{1}` will contain the certificate template name.
- Placeholder `{2}` will contain one or more warnings that have been logged during the processing of the certificate request.

### Event Description

This event gets logged if warnings occurred during the processing of the certificate request. This event will get logged regardless if the certificate gets issued or not.

> Warnings might indicate an abnormal condition. It is therefore recommended to collect these events and trigger an alert in your monitoring solution, if present.

Currently, TameMyCerts logs warnings in the following cases:

- A certificate request contains the dangerous "san" request attribute, which might be an indicator of an attempt to attack the certification authority. Refer to section [Denying certificate requests for insecure combinations](#deny-insecure-flags) for more information.
