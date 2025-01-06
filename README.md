# The "Tame My Certs" policy module for Active Directory Certificate Services certification authorities

![](https://github.com/Sleepw4lker/TameMyCerts/actions/workflows/badge-build.yml/badge.svg?branch=main&event=push)&nbsp;![](https://github.com/Sleepw4lker/TameMyCerts/actions/workflows/badge-xunit.yml/badge.svg?branch=main&event=push)

TameMyCerts is a [policy module](https://docs.microsoft.com/en-us/windows/win32/seccrypto/certificate-services-architecture) for Microsoft [Active Directory Certificate Services (AD CS)](https://docs.microsoft.com/en-us/windows/win32/seccrypto/certificate-services) enterprise certification authorities that enables security automation for a lot of use cases in the PKI field.

It supports, amongst other functions, inspecting certificate requests for certificate templates that allow the subject information to be specified by the enrollee against a defined policy. If any of the requested identities violates the defined rules, the certificate request automatically gets denied by the certification authority. Requested identities can also be mapped against Active Directory to apply restrictions based on group memberships. Issued certificates can be enriched with either static values, values from mapped Active directory objects, or by values from the original certificate request transferred into other certificate fields.

The module therefore helps you to tame the zoo of your certificates and use cases, and by doing so immensely **improves your PKI's security**! It has proven itself in countless environments of enterprise-grade scale.

> Besides enterprise grade production workloads, TameMyCerts' request inspection and logging capabilites empower the [Certiception](https://github.com/srlabs/Certiception) honeypot toolkit for AD CS to allow spotting adversaries trying to [abuse a Microsoft certification authority](https://posts.specterops.io/certified-pre-owned-d95910965cd2).

> **Commercial support**, **consulting services** and **maintenance agreements** are available on demand. [Contact me](https://www.gradenegger.eu/en/imprint/) for details if you are interested.

TameMyCerts is fully compatible with all AD CS' functions and protocols like NDES, CEP, and CES. It can be used in combination with any 3rd party application like Mobile Device Management (MDM) systems, from any vendor.

## Getting started

- Download ready-made binary packages from the [Releases](https://github.com/Sleepw4lker/TameMyCerts/releases) page here on GitHub.

- Consult the [user guide](https://docs.tamemycerts.com) to learn how to install, configure and use the module.

- Consult the [changelog](CHANGELOG.md) if upgrading from a previous version.

## Value Proposition

As a PKI operator, it is your responsibility to verify and confirm the enrollee's identity, and ensure he is permitted to request a certificate for the specified identity. As the certificate volume in a typical enterprise is quite high, it is common to automate the task of certificate issuance where possible. Active Directory Certificate Services offers the possibility to identify an enrollee by it's Active Directory identity (meaning the PKI delegates the identification job to AD) and build the certificate content based on this information.

Sadly, there are many cases where this is not possible. In these cases, a certificate request is usually put into pending state so that a certificate manager can review and approve/deny the certificate request. However, this contradicts the goal of automatization. Also, putting such a certificate request into pending state is often not possible due to technical reasons. In these cases, the identification job is delegated entirely to the enrollee, which can lead to serious security issues: Any subject information (e.g. logon identities of administrative accounts in user certificates, or fraudulent web addresses in web server certificates) can be specified which opens a large security gap, waiting to be [abused by attackers](https://www.gradenegger.eu/en/from-zero-to-enterprise-administrator-through-the-network-device-registration-service-ndes/).

The TameMyCerts policy module addresses, amongst others, the following use cases:

- Certificate issuance must be delegated to a 3rd party service, for example, Mobile Device Management (MDM) systems like [Microsoft Endpoint Manager (aka InTune)](https://www.microsoft.com/en-us/security/business/microsoft-endpoint-manager) or [VMware AirWatch/Workspace One](https://www.vmware.com/content/vmware/vmware-published-sites/de/products/workspace-one.html.html), [Network Device Enrollment Service (NDES)](https://social.technet.microsoft.com/wiki/contents/articles/9063.active-directory-certificate-services-ad-cs-network-device-enrollment-service-ndes.aspx) deployments or similar use cases that require the certificate template to be configured to have the enrollee supply the subject information with the certificate signing request in combination with direct certificate issuance. Without the module, there is absolutely no control over the issued certificate content.

- The module can also mitigate the problem that certificates may be inconsistent among platforms (e.g. having differing subject information on a mobile phone managed by MDM than on a PC that uses Autoenrollment because of inconsistent configuration settings on the MDM) by enforcing certificate content.

- It is also capable of ensuring that a user or computer account exists in Active Directory matching the requested certificate, and that it is enabled and member (or not) of specific security groups (e.g. this can prevent issuing certificates for administrative accounts via MDM).

- Modifying the Subject Distinguished Name (DN) or Subject Alternative Name (SAN) of issued certificates based on individual rules containing values from the opriginating certificate request or from Active Directory object attribues (e.g. supplementing Organizational Units, or issuing certificates containing the DisplayName or UPN as identity) via offline and online certificate requests.

- Adding the the newly introduced Security Identifier (SID) certificate extension (_szOID_NTDS_CA_SECURITY_EXT_ with object id 1.3.6.1.4.1.311.25.2 that was introduced with [KB5014754](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)) into offline certificate requests, which e.g. allows you to use Microsoft Network Policy Server (NPS) with certificates issued to mobile devices and the like and avoid breaking authentication when "strong" certificate mapping [will be enforced by Microsoft on February 11, 2025](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16#bkmk_fullenforcemode).

- Technical or legal requirements to allow any kind of Subject Relative Distinguished Name to be enabled for issuance on the certification authority (enabling [CRLF_REBUILD_MODIFIED_SUBJECT_ONLY](https://www.gradenegger.eu/en/use-of-undefined-relative-distinguished-names-rdn-in-issued-certificates/) flag on the certification authority). Without the module, there is no control over which exact Subject RDNs are allowed to be issued.

- Certificate templates configured to allow Elliptic Curve Cryptography (ECC) keys. Without the module, it would be possible that certificates get issued that use small RSA keys (e.g. 512 bit or even smaller) even though these would be not allowed in the certificate template configuration, as the Windows Default policy module [only validates the key length but not the key algorithm](https://www.gradenegger.eu/en/key-algorithm-is-not-checked-by-the-policy-module/).

- Issuance of certificates with a validity period within exactly defined timeframe (e.g. valid only exactly for one work shift), or having the requirement to have all certificates end by a specific date.

- Preventing Users to request certificates from templates that are intended to be used solely with [AutoEnrollment](https://www.gradenegger.eu/en/basics-manual-and-automatic-certificate-request-via-lightweight-directory-access-protocol-ldap-and-remote-procedure-call-distributed-common-object-model-rpc-dcom/) via alternative methods (e.g. MMC.exe).

- TameMyCerts is also the perfect companion for the [TameMyCerts REST API](https://github.com/Sleepw4lker/TameMyCerts.REST) for AD CS, the [TameMyCerts Certificate Enrollment Proxy](https://github.com/Sleepw4lker/TameMyCerts.WSTEP) for AD CS or the awesome [ACME-ADCS-Server](https://github.com/glatzert/ACME-Server-ADCS) project.
