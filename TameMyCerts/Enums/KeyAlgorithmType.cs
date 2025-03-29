namespace TameMyCerts.Enums;

/// <summary>
///     Public key algorithm types supported by the Microsoft certification authority.
/// </summary>
internal enum KeyAlgorithmType
{
    /// <summary>
    ///     The RSA algorithm.
    /// </summary>
    RSA = 1,

    /// <summary>
    ///     The DSA algorithm.
    /// </summary>
    DSA = 2,

    /// <summary>
    ///     The elliptic curve digital signature algorithm using the nistp256 curve.
    /// </summary>
    ECDSA_P256 = 3,

    /// <summary>
    ///     The elliptic curve digital signature algorithm using the nistp384 curve.
    /// </summary>
    ECDSA_P384 = 4,

    /// <summary>
    ///     The elliptic curve digital signature algorithm using the nistp521 curve.
    /// </summary>
    ECDSA_P521 = 5,

    /// <summary>
    ///     The elliptic curve diffie hellman algorithm using the nistp256 curve.
    /// </summary>
    ECDH_P256 = 6,

    /// <summary>
    ///     The elliptic curve diffie hellman algorithm using the nistp384 curve.
    /// </summary>
    ECDH_P384 = 7,

    /// <summary>
    ///     The elliptic curve diffie hellman algorithm using the nistp521 curve.
    /// </summary>
    ECDH_P521 = 8
}