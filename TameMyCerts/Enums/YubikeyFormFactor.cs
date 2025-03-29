using System.Xml.Serialization;

namespace TameMyCerts.Enums;

public enum YubikeyFormFactor
{
    [XmlEnum(Name = "Unknown")]
    UNKNOWN = 0,

    [XmlEnum(Name = "UsbAKeychain")]
    USB_A_KEYCHAIN = 1,

    [XmlEnum(Name = "UsbANano")]
    USB_A_NANO = 2,

    [XmlEnum(Name = "UsbCKeychain")]
    USB_C_KEYCHAIN = 3,

    [XmlEnum(Name = "UsbCNano")]
    USB_C_NANO = 4,

    [XmlEnum(Name = "UsbCLightning")]
    USB_C_LIGHTNING = 5,

    [XmlEnum(Name = "UsbABiometricKeychain")]
    USB_A_BIOMETRIC_KEYCHAIN = 6,

    [XmlEnum(Name = "UsbCBiometricKeychain")]
    USB_C_BIOMETRIC_KEYCHAIN = 7
}