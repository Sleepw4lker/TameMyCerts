# Monitoring and Troubleshooting {#troubleshooting}

> Please be aware that if no policy file exists for a given certificate template, the request gets accepted as this would be the original behavior of the Windows Default policy module. This behavior can however be changed by configuring a [global setting](#global-settings) for TameMyCerts.

If a certificate request violates the defined policy, the certification authority will deny it with one of the below error codes and messages. The CA will log Event with ID 53 (<https://www.gradenegger.eu/en/details-of-the-event-with-id-53-of-the-source-microsoft-windows-certificationauthority/>). The error code/message will also be handed over to the requesting client over the DCOM protocol as answer to the certificate request.

TameMyCerts will also write its own [Logs](#logs) which contain detailled information about why a certificate request was denied, amongst others.

## Error Codes {#error-codes}

The following error codes can be thrown by the policy module back to the
requestor when a request was denied:

|Message|Symbol|Description|
|---|---|---|
|The permissions on the certificate template do not allow the current user to enroll for this type of certificate. |**CERTSRV\_E\_TEMPLATE\_DENIED**|Occurs if the [process used to create the certificate request](#process-rules) is unknown, not allowed or explicitly disallowed. Also occurs when [Directory Services mapping](#ds-mapping) encounters an error.|
|The certificate has an invalid name. The name is not included in the permitted list or is explicitly excluded.|**CERT\_E\_INVALID\_NAME**|Occurs if the requests [Subject Distinghuished Name](#subject-rules) or [Subject Slternative Name](#san-rules) violates the defined rules.|
|The public key does not meet the minimum size required by the specified certificate template.|**CERTSRV\_E\_KEY\_LENGTH**|Occurs if the requests public key violates the defined rules for key algorithm or [maximum key length](#key-rules).|
|An internal error occurred.|**ERROR\_INVALID\_DATA**|Occurs if the policy module is unable to interpret the given [policy file](#configuring).|
|The specified time is invalid.|**ERROR\_INVALID\_TIME**|Occurs if an invalid date was requested for the ["StartDate"](#startdate) certificate request attribute.|

## Caches involved {#caches}

TameMyCerts features the following caches:

### Certificate Template Cache {#template-cache}

Certificate template configuration is read by TameMyCerts from the CA servers registry every 5 minutes to reduce CPU load.

Note that updates made to a certificate template in Active Directory are not instantly replicated to the CA servers registry, as this part of the registry is only updated every 8 hours.

### Certificate Request Policy Cache {#policy-cache}

Certificate Request policy files are loaded on first use and are then served from memory as long as they do not change. This reduces CPU and storage load. When the file gets modified and therefore the modification date of the file gets updated, it will get re-loaded on next use.

Should you, for example, copy a previous version of a policy configuration file back to the configured directory, it will not get read because it would have an older modification date. You would have to save it again so that it has a newer timestamp. Alternatively, you could re-start ehe certification authority service, as this will invalidate the cache.

## Known limitations, common issues and frequently asked questions {#limitations}

### Unsupported Subject Alternative Name (SAN) types

TameMyCerts currently does only support the following Subject Alternative Name types:

- dnsName
- rfc822Name
- uniformResourceIdentifier
- userPrincipalName
- ipAddress

If a certificate request contains an unsupported SAN type, the behavior is as follows:

- If the certificate template is an online template, this limitation doesn't matter.
- If the certificate template is an offline template,
  - If no policy configuration file exists, the SAN extension gets issued as requested.
  - If you don't modify the SAN of a requested certificate through a policy configuration, the SAN extension gets issued as requested.
  - If you modify the SAN of a requested certificate through a policy configuration, all unsupported SAN types get stripped from the issued certificates SAN extension.

### Interpreting the error message that a policy configuration file could not be parsed

When an error parsing the policy configuration file is thrown, remember that the actual line may be above or below the one noted in the log entry.

### A recently created certificate template is not recognized by TameMyCerts and an Error with ID 10 is logged

This is expected as there is a [chaching involved](#template-cache). The cache is read from the local certificate template cache of the CA server and updated every five minutes. Therefore, you can do one of the following to solve this:

1. Wait until the local certificate template gets updated automatically. This can take up to eight hours.

2. Update the local certificate template cache on your own. To do this, run the following command as an administrator:

        certutil -pulse

   You'll then still have to wait up to 5 minutes or restart the CA service afterwards for the certificate template to get recognized.

### Relative distinguished with empty values are treated as non-existent

Certificate requests that contain relative distinguished with empty values (e.g. CN="") are treated as if the RDN was missing when a subject rule is applied. This is because TameMyCerts doesn't inspect the actual certificate request but how the certification authority would issue the certificate. Microsoft AD CS does remove relative distinguished names containing empty values.

### No support for standalone certification authorities

As TameMyCerts follows [the original Microsoft concept of certificate templates](#how-it-works), it does not support standalone certification authorities (as these do not use certificate templates).

### No support for coexistence with other custom policy modules

At the moment, TameMyCerts can not be combined with other policy modules except the Windows Default policy module that is shipped with Active Directory Certificate Services. A common example for an incompatible module would be the policy modules shipped with Microsoft Identity Manager Certificate Management (MIM CM).
