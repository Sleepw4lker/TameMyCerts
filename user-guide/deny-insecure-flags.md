## Denying certificate requests for insecure combinations {#deny-insecure-flags}

> Applies to **online** and **offline** certificate templates.

TameMyCerts will automatically deny certificate requests when they contain a "san" request attribute and the certification authority has the insecure EDITF\_ATTRIBUTESUBJECTALTNAME2 (<https://www.gradenegger.eu/en/take-over-the-active-directory-overall-structure-with-the-flag-editf_attributesubjectaltname2/>) flag set. This combination can allow an attacker to request certificates with arbitrary identities, resulting in a complete takeover of your Active Directory. Therefore, this behavior can neither be configured nor disabled.

Instead of using the "san" request attribute in combination with **EDITF\_ATTRIBUTESUBJECTALTNAME2**, you should ensure that certificate request already contain a Subject Alternative Name (SAN) extension. In case where this is not possible, the [Supplementing DNS Names and IP Addresses](#supplement-dns-names) feature can be used.