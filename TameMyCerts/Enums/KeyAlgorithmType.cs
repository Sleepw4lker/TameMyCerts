using System;

namespace TameMyCerts.Enums;

[AttributeUsage(AttributeTargets.Field)]
internal class AlgorithmNameAttribute(string name) : Attribute
{
    public string Name { get; } = name;
}

/// <summary>
///     Public key algorithm types supported by the Microsoft certification authority.
/// </summary>
internal enum KeyAlgorithmType
{
    /// <summary>
    ///     The RSA algorithm.
    /// </summary>
    [AlgorithmName("RSA")] RSA = 1,

    /// <summary>
    ///     The DSA algorithm.
    /// </summary>
    [AlgorithmName("DSA")] DSA = 2,

    /// <summary>
    ///     The elliptic curve digital signature algorithm using the nistp256 curve.
    /// </summary>
    [AlgorithmName("ECDSA_P256")] ECDSA_P256 = 3,

    /// <summary>
    ///     The elliptic curve digital signature algorithm using the nistp384 curve.
    /// </summary>
    [AlgorithmName("ECDSA_P384")] ECDSA_P384 = 4,

    /// <summary>
    ///     The elliptic curve digital signature algorithm using the nistp521 curve.
    /// </summary>
    [AlgorithmName("ECDSA_P521")] ECDSA_P521 = 5,

    /// <summary>
    ///     The elliptic curve diffie hellman algorithm using the nistp256 curve.
    /// </summary>
    [AlgorithmName("ECDH_P256")] ECDH_P256 = 6,

    /// <summary>
    ///     The elliptic curve diffie hellman algorithm using the nistp384 curve.
    /// </summary>
    [AlgorithmName("ECDH_P384")] ECDH_P384 = 7,

    /// <summary>
    ///     The elliptic curve diffie hellman algorithm using the nistp521 curve.
    /// </summary>
    [AlgorithmName("ECDH_P384")] ECDH_P521 = 8,

    /// <summary>
    ///     The Module Lattice-based Digital Signature Algorithm (ML-DSA)
    ///     using parameter set 44 (NIST security level 2, comparable to AES-128).
    /// </summary>
    [AlgorithmName("ML-DSA:44")] ML_DSA_44 = 9,

    /// <summary>
    ///     The Module Lattice-based Digital Signature Algorithm (ML-DSA)
    ///     using parameter set 65 (NIST security level 3, comparable to AES-192).
    /// </summary>
    [AlgorithmName("ML-DSA:65")] ML_DSA_65 = 10,

    /// <summary>
    ///     The Module Lattice-based Digital Signature Algorithm (ML-DSA)
    ///     using parameter set 87 (NIST security level 5, comparable to AES-256).
    /// </summary>
    [AlgorithmName("ML-DSA:87")] ML_DSA_87 = 11
}