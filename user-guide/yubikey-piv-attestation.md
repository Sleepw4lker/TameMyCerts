## YubiKey PIV attestation {#yubikey-piv-attestation}

> Applies to **online** and **offline** certificate templates.

> TameMyCerts YubiKey PIV attestation is the first utliziing Event Tracing for Windows (ETW) for logging. Yubikey validation will log which policy was matched in the Operations log, the entry will also include information about the YubiKey.

TameMyCerts can ensure that a key pair has been created and is secured with a Yubikey (<https://www.yubico.com/products/yubikey-5-overview/>).

This feature is called Personal Identity Verification (PIV) attestation (<https://developers.yubico.com/PIV/Introduction/PIV_attestation.html>). It can be combined with any other TameMyCerts feature.

It is possible to include the attestion certificates in the Certificate Signing Request by using any of the following means:

- yubico-piv-tool (<https://developers.yubico.com/yubico-piv-tool/>), a vendor maintained software for managing yubico PIV application.
- powershellYK (<https://github.com/virot/powershellYK>), a PowerShell 7 module that builds on the Yubico .NET SDK. Available on Windows and MacOS.
- onboardYK (<https://github.com/virot/onboardYK>), a .NET 8 application for easy enrollment in a Windows environment. It allows for default for endusers and more advanced configurations.

You define a **YubiKeyPolicies** directive containing one or more **YubiKeyPolicy** rules.

|Parameter|Mandatory|Description|
|---|---|---|
|Action|**yes**|Specifies if this rule shall cause the certificate request to be allowed or denied, should it's conditions match. Can be `Allow` or `Deny`.|
|PinPolicy|no|Specifies which PIN policy must be configured on the Yubikey for the rule to match. Can be one or more of the following: `Once`, `Never`, `Always`, `MatchOnlye`, `MatchAlways`|
|TouchPolicy|no|Specifies which Touch policy must be configured on the Yubikey for the rule to match. Can be one or more of the following: `Always`, `Never`, `Cached`|
|FormFactor|no|Specifies of which form factor the Yubikey must be for the rule to match. Can be one or more of the following: `UsbAKeychain`, `UsbCKeychain`, `UsbANano`, `UsbCNano`, `UsbCLightning`, `UsbABiometricKeychain`, `UsbCBiometricKeychain`|
|MaximumFirmwareVersion|no|Specifies the maximum Firmware version the Yubikey must have for the rule to match.|
|MinimumFirmwareVersion|no|Specifies the minimum Firmware version the Yubikey must have for the rule to match.|
|Edition|no|Specifies of which edition the Yubikey must be for the rule to match. Can be one or more of the following: `FIPS`, `Normal`, `CSPN`|
|Slot|no|Specifies the Slot under which the certificate request must be stored under for the rule to match. Can be one or more of the following: `9a`, `9c`, `9d`, `9e`|
|KeyAlgorithm|no|Specifies the Key Algorithm of which the certificate request must be for the rule to match. Can be one or more of the following: `RSA`, `ECC`|

### How Yubikey policies are processed

The YubiKeyPolicies are read one by one.

- If there is **any** policy with `Allow` action, the default behavior if no rule matched is to **deny** the certificate request.
- If **all** policies are of `Deny` action, the default behavior if no rule matched is to **allow** the certificate request.
- Alternating Deny and Allow policies is allowed. In this case, for a certificate request to get allowed, **at least one** of the policy with `Allow` action must match, whereas **none** of the policies with `Deny` action must match.

### Transferring PIV attestation data into issued certificates

Attestation Information can also be [written into the Subject Distinguished Name](#modify-subject-dn) of the issued certificates:

- yk.FormFactor
- yk.FirmwareVersion
- yk.PinPolicy
- yk.TouchPolicy
- yk.Slot
- yk.SerialVersion

### Preparing the certification authority

For the attestation certificate chain to be properly built, you must create a `YKROOT` certificate store under the `LocalMachine` certificate store on the certification authority server.

```powershell
cd Cert:\LocalMachine\My
New-Item -Name YKROOT
```

The Yubikey attestation Root CA certificate (<https://developers.yubico.com/PIV/Introduction/piv-attestation-ca.pem>) must be installed into the newly created `YKROOT` certificate store.

### Configuring

Denying certificate requests for ECC keys with a Yubikey with firmware version prior to 5.7.0.

```xml
<YubiKeyPolicies>
  <YubiKeyPolicy>
      <MaximumFirmwareVersion>5.6.9</MaximumFirmwareVersion>
      <KeyAlgorithm>
        <string>ECC</string>
      </KeyAlgorithm>
      <Action>Deny</Action>
  </YubiKeyPolicy>
</YubiKeyPolicies>
```

Transferring the Slot and Serial Number of the Yubikey into the _commonName_ of the issued certificate (in combination with the `cn` attribute from a [mapped](#ds-mapping) Active Directory object).

```xml
<OutboundSubject>
  <OutboundSubjectRule>
    <Field>commonName</Field>
    <Value>{ad:cn} [{yk:Slot} {yk:SerialNumber}]</Value>
    <Mandatory>true</Mandatory>
    <Force>true</Force>
  </OutboundSubjectRule>
</OutboundSubject>
```

A policy containing all possible combinations.

```xml
<YubiKeyPolicies>
  <YubiKeyPolicy>
    <Action>Allow</Action>
    <PinPolicy>
      <string>Once</string>
      <string>Never</string>
      <string>Always</string>
      <string>MatchOnce</string>
      <string>MatchAlways</string>
    </PinPolicy>
    <TouchPolicy>
      <string>Always</string>
      <string>Never</string>
      <string>Cached</string>
    </TouchPolicy>
    <FormFactor>
      <string>UsbAKeychain</string>
      <string>UsbCKeychain</string>
      <string>UsbANano</string>
      <string>UsbCNano</string>
      <string>UsbCLightning</string>
      <string>UsbABiometricKeychain</string>
      <string>UsbCBiometricKeychain</string>
    </FormFactor>
    <MaximumFirmwareVersion>9.9.9</MaximumFirmwareVersion>
    <MinimumFirmwareVersion>0.0.0</MinimumFirmwareVersion>
    <Edition>
      <string>FIPS</string>
      <string>Normal</string>
      <string>CSPN</string>
    </Edition>
    <Slot>
      <string>9a</string>
      <string>9c</string>
      <string>9d</string>
      <string>9e</string>
    </Slot>
    <KeyAlgorithm>
      <string>RSA</string>
      <string>ECC</string>
    </KeyAlgorithm>
  </YubiKeyPolicy>
</YubiKeyPolicies>
```
