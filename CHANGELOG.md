## Changelog for the TameMyCerts policy module {#changelog}

> TameMyCerts has evolved into a reliable, secure and stable enterprise product. Many organizations around the world are relying on it to improve their security and their PKI workflows. Professional development, testing and documentation consumes a considerable amount of time and resources. Whilst still being fully committed on keeping source code available for the community, _digitally signed binaries_, a _print-optimized documentation_ and _priority support_ are benefits **only available for customers with an active maintenance contract**.

### Verison 1.8.xx

_This version was not yet released._

- Add new `Continue` action for Directory Services mapping that will cause the certificate request not getting denied when no object could be found.
- Subject Alternative Names can be removed via an empty `Value` in a `OutboundSubjectRule` the same way as it was already possible for the Subject Distinguished Name.

### Version 1.7.1609.1089

_This version was released on May 29, 2025._

- The code base has been upgraded from .NET Framework 4.7.2 to .NET 8.0. Files are no longer installed into the System32 folder but under the Program Files directory. Also, the [.NET 8.0 Desktop Runtime](https://dotnet.microsoft.com/en-us/download/dotnet/8.0) must be installed.
- Policy configuration files are now strictly processed, means that there will be errors raised when they contain invalid nodes. This may especially affect the following:
  - If policy configuration files still contain `KeyAlgorithm` nodes (which were removed with version 1.6), these must be removed from the configuration files.
  - The `Action` directives as well as the `TreatAs` directives for `Pattern` directives as processed case-sensitive, means that they must be specified exactly as documentated.
- Directory Services Mapping is now able to honor nested group memberships and resolve primary Groups (#38).
  - This is enabled by default and requires all Domain Controllers targeted by TameMyCerts to run on Windows Server 2016 or newer. It can be disabled via global flag.
- Directory Services Mapping now supports restricting certificate issuance based on remaining password validity time (#34).
- Introducing a new Validator enabling to verify [Yubikey PIV attestation](https://developers.yubico.com/PIV/Introduction/PIV_attestation.html) with a Microsoft certification authority (thanks to the contribution of Oscar Virot).
- Introducing (verbose) Event IDs 12 and 13 that indicate certificate requests getting issued or put into pending state.
- Introduding Event 14 which will contain warnings that occurred during the processing of a certificate request.
  - Currently, the detection of the `san` request attribute will get logged regardless if the dangerous `EDITF_ATTRIBUTESUBJECTALTNAME2` flag is enabled or not.
  - This new behavior allows to silently [detect attack attempts](https://github.com/srlabs/Certiception) on the certification authority without raising suspicion.
- Introducing a `SupplementUnqualifiedNames` switch to use in combination with supplementing of DNS names (both `SupplementDnsNames` and `SupplementServicePrincipalNames`). To keep compatibility with the previous behavior, this setting defaults to `true`. If set to `false`, supplementation logic will not include DNS names that are not fully qualified.
- Directory Services mapping can now be configured to deny a certificate request in the case a matching object was found in the directory.
- Introducing global settings for TameMyCerts which allows to define behavior that applies globally, regardless of the defined certificate templates (the default behavior stays as before):
  - Allow to set the default behavior to globally deny a certificate request when no policy configuration file is found for the requested certificate template.
  - Allow to certificate requests containing insecure request attribute and certification authority flag combinations to get issued (**Only for testing purposes. Use at your own risk!**).
  - Disable the resolving of nested Group Memberships.
- Introducing support for adding custom certificate extensions with static values to issued certificates (e.g. OCSP Must-staple or Microsoft Hyper-V/SCVMM Virtual Machine Connection).
- Fix the module denying certificate requests with error 0x80131500 when the certificate request contains a Subject Alternative Name extension with empty content (#20).
- Fix the installer script not removing the event source on uninstall (#22).
- Since Windows Server 2012 R2 is now out of support by Microsoft, support by TameMyCerts has been dropped as well.
- Improved documentation, especially description of event logs and use cases.

### Version 1.6.1045.1129

_This version was released on Nov 12, 2023._

This is a major release containing lots of bug fixes for edge-cases as well as many new exciting features, whilst (mostly) staying backwards-compatible to existing configuration files.

- TameMyCerts now supports modifying the Subject Distinguished Name and Subject Alternative Name of issued certificates with attributes of mapped Active Directory objects, values from certificate request fields, static strings, or a combination of all these. **Note that this breaks existing policy files. These must be adjusted when upgrading.**
- TameMyCerts now implements caching for policy configuration files. Instead of loading them over and over again for any incoming request, this is now only done if the file has changed..
- TameMyCerts now supports configuring per-Template CRL Distribution Point, Authority Information Access, and Online Certificate Status Protocol URIs. Configure them with the `CrlDistributionPoints`, `AuthorityInformationAccess` and `OnlineCertificateStatusProtocol` directives.
- TameMyCerts now automatically determines the desired key algorithm from the certificate template. The `KeyAlgorithm` parameter has therefore been removed. Existing configurations will continue to work but without using the configured `KeyAlgorithm`.
- TameMyCerts now reads all available request properties directly from the certification authority instead of parsing the inline request. The inline certificate request will now only be parsed when `AllowedProcesses` or `DisallowedProcesses` directives are configured, as this information cannot be obtained from the CA directly. There are rare cases where it may not be possible to parse the inline certificate request. In this case, the requested properties will be treated as non-existent.
- TameMyCerts now supports the DSA key algorithm for incoming certificate requests.
- TameMyCerts now detects if a resulting certificate wouldn't contain any identity, and will deny such a request by default. This allows to make both `commonName` and Subject Alternative Name fields optional at the same time in a policy, whilst ensuring a certitificate request has one of them set. The behavior can be disabled with the `PermitEmptyIdentities` parameter.
- Directory Services mapping now supports the `SupplementServicePrincipalNames` directive. This mode allows to automatically add all DNS names found in the Service Principal Names (SPNs) of mapped AD objects to the SAN extension of issued certificates.
- Directory Services mapping now allows to specify `Pattern` directives like in Subject or SAN rules that can get applied all of the attributes that can be used for building the Subject Distingushed Name.
- Directory Services mapping now allows to filter based on organizational unit memberships of mapped AD objects with the `AllowedOrganizationalUnits` and `DisallowedOrganizationalUnits` parameters.
- Directory Services mapping now allows adding the SID of a mapped AD object into the Subject Alternative Name (SAN) extension of an issued certificate [as introduced by Microsoft in April 2023](https://techcommunity.microsoft.com/blog/AskDS/preview-of-san-uri-for-certificate-strong-mapping-for-kb5014754/3789785). The directive is called `AddSidIUniformResourceIdentifier`.
- `Pattern` directives now support the new `RegExIgnoreCase` kind for the `TreatAs` attribute, which allows a regular expression to be treated case-insensitive.
- `Pattern` directives now support the new `ExactMatch` and `ExactMatchIgnoreCase` kinds for the `TreatAs` attribute, which allow simple value comparisons, either case sensitive or case-insensitive.
- `Pattern` directives now support matching IPv6 addresses against CIDR masks when `TreatAs` is set to `Cidr`. 
- Supplementing DNS names from the Subject DN can now append missing entries to an existing SAN certificate extension (instead of only building a new one as it was before). Same goes for all other cases that potentially build or modify the SAN extension.
- The new mode to interpret the Subject Distinguished Name introduced with version 1.5 now correctly handles multiple RDNs of same type.
- When TameMyCerts is unable to interpret a policy configuration file, the error message now contains more detailed information about the possible cause.
- Fix a bug causing to allow blacklisted patterns when an invalid kind for the `TreatAs` attribute was specified for a `Pattern` in a Subject or SAN rule.
- Fix a bug potentially allowing LDAP injections via requested certificate content.
- Fix a bug causing requests getting denied when a template name contains invalid file name characters.
- Fix a bug in the installer script preventing to run it without arguments.

### Version 1.5.760.827

_This version was released on Jan 31, 2023._

This is a quality improvement only release. TameMyCerts now uses the interfaces provided by the certification authority to determine Subject and Subject Alternative Name information.

- Fix a security vulnerability causing nested certificate requests to bypass subject alternative name rule processing. **All users of previous versions are urged to upgrade!**
- Subject RDN inspection is now done against the properties constructed by the certification authority (how the CA would issue the certificate. Previously it was done against the original inline PKCS#10 certificate request). This should enhance compatibility with malformed certificate requests but does not work with undefined relative distinguished names. Behavior can be changed back to previous logic by setting `ReadSubjectFromRequest` to true in request policy.
- Enhance logging for directory service query failures.
- Refactor the code for building the security identifier certificate extension.

### Version 1.4.728.502

_This version was released on Dec 30, 2022._

This is a quality improvement only release. TameMyCerts is now covered by automated integration tests which allow testing parts of the code base otherwise not testable with unit tests.

- Fix a bug causing directory mapping not finding all of mapped object's attributes when using global catalog (no SearchRoot configured in policy) to find an object.
- Fix a bug causing to not display the correct error message in case no connection to Active Directory is possible during directory validation.
- Fix a bug causing certificate modifications made by TameMyCerts are not applied when a template is configured to put requests in pending state.
- Fix a bug causing to falsely log that a certificate request would get denied even if there is no reason to when policy is configured in audit mode.
- Fix a bug causing the StartDate request attribute not getting applied if no policy is configured for the given certificate template.
- Fix a bug causing request attributes to get processed case-sensitive which would allow circumventing security measures.
- Fix a bug causing directory mapping to fail when the userPrincipalName attribute is not populated for an account (even if is was not used for mapping). Due to this, mapped accounts are now identified and logged with their distinguishedName attribute instead oder userPrincipalName.
- Fix a bug causing an exception with directory mapping when the telexNumber directory attribute is populated for an object, as the property is not of string data type. Support for the telexNumber directory attribute has therefore been dropped.
- Fix a bug causing requests using a valid process name to get denied when only DisallowedProcesses is configured.
- Fix a bug causing requests using a valid cryptographic provider to get denied when only DisallowedCryptoProviders is configured.
- Attributes used for modification of a certificate's subject distinguished name are now only retrieved from AD if the feature is enabled for a certificate template.

### Version 1.3.683.747

_This version was released on Nov 15, 2022._

- Implement support for (over)writing the subject relative distinguished name (RDN) of issued certificates with configurable attributes from a mapped Active Directory object.
- Implement support for supplementing missing DNS names and IP addresses from commonName field in subject distringushed name into the subject alternative name of the issued certificate. This is to automatically make issued certificates compliant to [IETF RFC 2818](https://www.rfc-editor.org/rfc/rfc2818).
- Add option to issue certificates for mapped acounts that are disabled (e.g. to prestage certificates in combination with the `StartDate` attribute functionality).
- Add option to remove Security Identifier (`szOID_NTDS_CA_SECURITY_EXT`) certificate extension when provided in a certificate request instead of denying it entirely (`Remove` keyword for the SecurityIdentifierExtension directive).
- Key rules can now also be applied to requests for online certificate templates.
- Fix string substitution for the `serialNumber`, `unstructuredName` and `unstructuredAddress` relative distinguished name types.
- Fix a bug preventing the use of the "any" IPv4 CIDR mask (`0.0.0.0/0`) in a subject rule.
- Fix a bug in installer script not updating policy directory.

### Version 1.2.587.662

_This version was released on Aug 11, 2022._

- Implement support for looking up identities that are requested in offline templates against Active Directory (called "directory mapping"). It may be specified if a certificate request shall get denied if a matching user or computer account does not exist, is disabled, if it is member of a forbidden group, or not member of any permitted group.
- Implement support for adding the new Security Identifier (`szOID_NTDS_CA_SECURITY_EXT` with object id `1.3.6.1.4.1.311.25.2`) certificate extension that was introduced with [KB5014754](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16) to certificates issued for offline certificate requests (requires directory mapping). This should enable users to prevent authentication to fail when strong certificate mapping will be enforced on February 11, 2025.
- Implement protection against forgery of the `szOID_NTDS_CA_SECURITY_EXT` certificate extension by the enrollee. Policy can be configured to deny or allow offline requests containing this extension (default is to deny).
- Implement support for specifying a fixed expiration date on a per-template basis.
- Implement proper logging for processing of the `StartDate` request attribute and align behavior with Windows Default policy module.
- Fix a bug causing the module to return the validation result too early. This had no effect on security but not all violations against the ruleset would get logged, making troubleshooting somewhat more difficult.
- Fix a bug causing the module to throw an exception in the case a SAN extension could not be parsed.
- Fix the `organizationalUnitName` RDN to align with X.520 specifications (it was wrongly called `organizationalUnit` in earlier versions). **Note that this breaks existing policy files. These must be adjusted when upgrading.**
- Remove code for denying certificate requests containing the Subject Directory Atttributes (`2.5.29.9`) request extension, as this is disabled for issuance on AD CS by default anyway.
- Remove excessive calling of garbage collection which should improve processing performance.

### Version 1.1.432.1215

_This version was released on Mar 10, 2022._

- Change logic for allowed and disallowed patterns on SubjectRule directives. Now, for each defined "field" it is possible to specify how the expression will get treated (regular expression or CIDR notation), which allows for IP addresses to get verified if they are present in fields other that the iPAddress alternative name field. **Note that this breaks existing policy files. These must be adjusted when upgrading.**
- Implement support for applying rules on process names used to create certificate requests for both online and offline certificate templates.
- Implement support for applying rules on cryptographic providers used to create certificate requests' private keys for both online and offline certificate templates.
- Implement support for custom NotBefore date on a certificate with the `StartDate` request attribute, in analogy to the `ExpirationDate` request attribute supported by the Windows Default policy module.
- Implement basic protection against abuse of having the [EDITF\_ATTRIBUTESUBJECTALTNAME2](https://www.gradenegger.eu/?lang=en&p=1486) flag enabled. Requests with a `san` attribute get denied if the flag is enabled.
- Fix a bug causing the module to log an exception for requests with invalid `ExpirationDate` attribute.
- `SubjectRule` `Field` definition is now processed case insensitive.
- Change required [.NET Framework 4.7.2](https://support.microsoft.com/en-us/topic/microsoft-net-framework-4-7-2-offline-installer-for-windows-05a72734-2127-a15d-50cf-daf56d5faec2) due to [end of life](https://docs.microsoft.com/en-us/lifecycle/products/microsoft-net-framework) of previously used version 4.6.
- General code optimization that should slightly increase processing performance and overall maintainability of the code.
- install.ps1 is now also digitally signed.

### Version 1.0.410.1186

_This version was released on Feb 15, 2022._

This is the initial release of TameMyCerts made publicly available.