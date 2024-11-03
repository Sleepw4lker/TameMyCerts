﻿// Copyright 2021-2023 Uwe Gradenegger <uwe@gradenegger.eu>

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

using TameMyCerts.Enums;

namespace TameMyCerts.Models;

internal class CertificateTemplate
{
    public CertificateTemplate(string name, bool enrolleeSuppliesSubject, KeyAlgorithmType keyAlgorithm,
        bool userScope = false, string oid = null)
    {
        Name = name;
        Oid = oid ?? string.Empty;
        EnrolleeSuppliesSubject = enrolleeSuppliesSubject;
        UserScope = userScope;
        KeyAlgorithm = keyAlgorithm;
    }

    public string Name { get; }
    public string Oid { get; }
    public bool EnrolleeSuppliesSubject { get; }
    public bool UserScope { get; }
    public KeyAlgorithmType KeyAlgorithm { get; }

    public KeyAlgorithmFamily KeyAlgorithmFamily
    {
        get
        {
            switch (KeyAlgorithm)
            {
                case KeyAlgorithmType.DSA: return KeyAlgorithmFamily.DSA;
                case KeyAlgorithmType.ECDH_P256: return KeyAlgorithmFamily.ECC;
                case KeyAlgorithmType.ECDH_P384: return KeyAlgorithmFamily.ECC;
                case KeyAlgorithmType.ECDH_P521: return KeyAlgorithmFamily.ECC;
                case KeyAlgorithmType.ECDSA_P256: return KeyAlgorithmFamily.ECC;
                case KeyAlgorithmType.ECDSA_P384: return KeyAlgorithmFamily.ECC;
                case KeyAlgorithmType.ECDSA_P521: return KeyAlgorithmFamily.ECC;
                case KeyAlgorithmType.RSA: return KeyAlgorithmFamily.RSA;
                default: return KeyAlgorithmFamily.UNKNOWN;
            }
        }
    }
}