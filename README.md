# The "Tame My Certs" policy module for Active Directory Certificate Services

> **Note**
> **Commercial support** and **maintenance agreements** are available on demand. [Contact me](https://www.gradenegger.eu/?page_id=7) for details if you are interested.

TameMyCerts is a [policy module](https://docs.microsoft.com/en-us/windows/win32/seccrypto/certificate-services-architecture) for Microsoft [Active Directory Certificate Services (AD CS)](https://docs.microsoft.com/en-us/windows/win32/seccrypto/certificate-services) enterprise certification authorities that enables security automation for a lot of use cases in the PKI field.

The module supports, amongst other functions, inspecting certificate requests for certificate templates that allow the subject information to be specified by the enrollee against a defined policy. If any of the requested identities violates the defined rules, the certificate request automatically gets denied by the certification authority. Requested identities can also be mapped against Active Directory to apply restrictions based on group memberships, or even to pull certificate content from AD.

The module therefore helps you to tame your certs! It has proven itself in countless environments of enterprise-grade scale.

## Getting started

Find the most recent version of TameMyCerts as a ready-to-use, digitally signed binary package on the [releases page](https://github.com/Sleepw4lker/TameMyCerts/releases).

Consult the [user guide](https://docs.tamemycerts.com/) to learn how to install, configure and use the module.

Consult the [changelog](CHANGELOG.md) if upgrading from a previous version.

## Value Proposition

As a PKI operator, it is your responsibility to verify and confirm the enrollee's identity, and ensure he is permitted to request a certificate for the specified identity. As the certificate volume in a typical enterprise is quite high, it is common to automate the task of certificate issuance where possible. Active Directory Certificate Services offers the possibility to identify an enrollee by it's Active Directory identity (meaning the PKI delegates the identification job to AD) and build the certificate content based on this information.

Sadly, there are many cases where this is not possible. In these cases, a certificate request is usually put into pending state so that a certificate manager can review and approve/deny the certificate request. However, this contradicts the goal of automatization. Also, putting such a certificate request into pending state is often not possible due to technical reasons. In these cases, the identification job is delegated entirely to the enrollee, which can lead to serious security issues: Any subject information (e.g. logon identities of administrative accounts in user certificates, or fraudulent web addresses in web server certificates) can be specified which opens a large security gap, waiting to be [abused by attackers](https://www.gradenegger.eu/?lang=en&p=13269).

The TameMyCerts policy module addresses, amongst others, the following use cases:

- Certificate issuance must be delegated to a 3rd party service, for example, Mobile Device Management (MDM) systems like [Microsoft Endpoint Manager (aka InTune)](https://www.microsoft.com/en-us/security/business/microsoft-endpoint-manager) or [VMware AirWatch/Workspace One](https://www.vmware.com/content/vmware/vmware-published-sites/de/products/workspace-one.html.html), [Network Device Enrollment Service (NDES)](https://social.technet.microsoft.com/wiki/contents/articles/9063.active-directory-certificate-services-ad-cs-network-device-enrollment-service-ndes.aspx) deployments or similar use cases that require the certificate template to be configured to have the enrollee supply the subject information with the certificate signing request in combination with direct certificate issuance. Without the module, there is absolutely no control over the issued certificate content.
- The module can also mitigate the problem that certificates may be inconsistent among platforms (e.g. having differing subject information on a mobile phone managed by MDM than on a PC that uses Autoenrollment because of inconsistent configuration settings on the MDM) by enforcing certificate content.
- It is also capable of ensuring that a user or computer account exists in Active Directory matching the requested certificate, and that it is enabled and member (or not) of specific security groups (e.g. this can prevent issuing certificates for administrative accounts via MDM).
- Modifying the Subject Distinguished Name (DN) or Subject Alternative Name (SAN) of issued certificates based on individual rules containing values from the opriginating certificate request or from Active Directory object attribues (e.g. supplementing Organizational Units, or issuing certificates containing the DisplayName or UPN as identity) via offline and online certificate requests.
- Adding the the newly introduced Security Identifier (szOID_NTDS_CA_SECURITY_EXT with object id 1.3.6.1.4.1.311.25.2 that was introduced with [KB5014754](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)) extension into offline certificate requests, which e.g. allows you to use Microsoft Network Policy Server (NPS) with certificates issued to mobile devices and the like and avoid breaking authentication when "strong" certificate mapping [will be enforced by Microsoft on February 11, 2025](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16#bkmk_fullenforcemode).
- Technical or legal requirements to allow any kind of Subject RDN to be enabled for issuance on the certification authority (enabling [CRLF_REBUILD_MODIFIED_SUBJECT_ONLY](https://www.gradenegger.eu/?lang=en&p=952) flag on the certification authority). Without the module, there is no control over which exact Subject RDNs are allowed to be issued.
- Certificate templates configured to allow Elliptic Curve Cryptography (ECC) keys. Without the module, it would be possible that certificates get issued that use small RSA keys (e.g. 512 bit or even smaller) even though these would be not allowed in the certificate template configuration, as the Windows Default policy module [only validates the key length but not the key algorithm](https://www.gradenegger.eu/?lang=en&p=14138).
- Issuance of certificates with a validity period within exactly defined timeframe (e.g. valid only exactly for one work shift), or having the requirement to have all certificates end by a specific date.
- Preventing Users to request certificates from templates that are intended to be used solely with [AutoEnrollment](https://www.gradenegger.eu/?lang=en&p=2789) via alternative methods (e.g. MMC.exe).
- TameMyCerts is also the perfect companion for the [AdcsToRest](https://github.com/Sleepw4lker/AdcsToRest) REST API for AD CS or the awesome [ACME-ADCS-Server](https://github.com/glatzert/ACME-Server-ADCS) project.
