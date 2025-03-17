## YubiKey PIV attestation

The basic fuctionality of TameMyCerts in regards to YubiKeys are the same as regular TameMyCerts, with the addition that you can verify if a Certificate Request comes from a genuine YubiKey.
The YubiKeyPolicies are read one by one. If there are any Allow YubiKeyPolicy, the default if no rule is hit is Deny. If all policies are deny, the default is allow.
If a Allow YubiKeyPolicy is read the module will approve the request. Alternating Deny and Allow policies is allowed.
TameMyCerts YubiKey part is the first utliziing ETW for logging. YubiKeyValidator will log which policy was matched in the Operations log, the entry will also include information about the YubiKey.

Configuration:
It uses the same xml as the rest of TameMyCerts. The inital xml tag is 'YubiKeyPolicies' it includes the 'YubiKeyPolicy's.
A full configuration:

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

Just pick what you need to verfy and stick in your policy.

Before YubiKey 5.7.0 there is a but in the software for ECC keys, TMC allows for denying just those by having a first YubiKeyPolicy like this:

```xml
<YubiKeyPolicy>
    <MaximumFirmwareVersion>5.6.9</MaximumFirmwareVersion>
    <KeyAlgorithm>
      <string>ECC</string>
    </KeyAlgorithm>
    <Action>Deny</Action>
</YubiKeyPolicy>
```

Interacting with other parts of TMC
It is possible to update the Subject and SubjectAltName parts with data from the YubiKey attestion data.

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

attributes allowed from YubiKey attestiondata:
yk.FormFactor
yk.FirmwareVersion
yk.PinPolicy
yk.TouchPolicy
yk.Slot
yk.SerialVersion

### How to test

TameMyCerts has been extended to allow validation of CSRs that include the YubiKey attestion certificates.
It is a possible to include the attestion certificates in the CSR by using any of the following means:

- yubico-piv-tool
- powershellYK
- onboardYK

yubico-piv-tool
Yubico-piv-tool is a vendor maintained software for managing yubico PIV application.
url: https://developers.yubico.com/yubico-piv-tool/
example:

```
yubico-piv-tool --slot=9a --action=generate --pin-policy=once --touch-policy=cached --algorithm=ECCP384 --output=pubkey
yubico-piv-tool --slot=9a --subject="/CN=foo/OU=test/O=example.com/" --input=pubkey --attestation --output=request.csr --action=verify-pin --action=request
```

powershellYK
PowershellYK is a pwsh module that builds on the Yubico .NET SDK to allow managed YubiKeys with Powershell 7+. Available on Windows and MacOS.
url: https://github.com/virot/powershellYK
installation:

```pwsh
Install-Module -Name powershellYK
```

example:
This assumes that you have a new YubiKey, the default PIN for the PIV part of a YubiKey is 123456.

```pwsh
Connect-YubiKey
Connect-YubiKeyPIV
New-YubiKeyPIVKey -slot "PIV Authentication" -PinPolicy Always -TouchPolicy Cached -Algorithm EccP384
Build-YubiKeyPIVCertificateSigningRequest -Slot "PIV Authentication" -Subjectname "CN=CSR for TameMyCerts" -Attestation -OutFile attested.csr
Import-YubikeyPIV -Slot "PIV Authentication" -Certificate signed.cer
```

onboardYK
OnboardYK is .NET 8 application for easy enrollment in a Windows environment. The application is configured with a xml file, just as TameMyCerts. It allows for default for endusers and more advanced configurations.
url: https://github.com/virot/onboardYK