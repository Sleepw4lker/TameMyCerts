namespace TameMyCerts.Enums;

/// <summary>
///     Constants from Yubico
///     https://developers.yubico.com/PIV/Introduction/PIV_attestation.html
/// </summary>
internal static class YubikeyX509Extension
{
    public const string FIRMWARE = "1.3.6.1.4.1.41482.3.3";
    public const string SERIALNUMBER = "1.3.6.1.4.1.41482.3.7";
    public const string PIN_TOUCH_POLICY = "1.3.6.1.4.1.41482.3.8";
    public const string FORMFACTOR = "1.3.6.1.4.1.41482.3.9";
    public const string FIPS_CERTIFIED = "1.3.6.1.4.1.41482.3.10";
    public const string CPSN_CERTIFIED = "1.3.6.1.4.1.41482.3.11";
    public const string ATTESTATION_INTERMEDIATE = "1.3.6.1.4.1.41482.3.2";
    public const string ATTESTATION_DEVICE = "1.3.6.1.4.1.41482.3.1";
    public const string ATTESTATION_DEVICE_PIVTOOL = "1.3.6.1.4.1.41482.3.11";
}