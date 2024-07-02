// Copyright 2021-2023 Uwe Gradenegger <uwe@gradenegger.eu>

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

namespace TameMyCerts.Enums
{
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
}