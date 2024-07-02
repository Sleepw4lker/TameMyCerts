## Audit only mode {#audit-only-mode}

> Applies to **online** and **offline** certificate templates.

TameMyCerts supports an Audit-only mode, in which certificate requests get allowed regardless of the verification result. This helps by sharpending policies before applying them to existing deployments. If a certificate request would be denied in regular mode, TameMyCerts will [log this to the event log](#logs) of the certification authority to allow administrators further research.

![Audit only mode is enabled for this certificate template. Policy violations will get logged, but the certificate will get issued.](resources/audit-only-mode.png)

### Configuring

You enable Audit only mode by configuring the **AuditOnly** directive.

```xml
<AuditOnly>true</AuditOnly>
```