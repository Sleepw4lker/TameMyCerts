// Copyright 2021-2025 Uwe Gradenegger <info@gradenegger.eu>

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

using System;

namespace TameMyCerts.X509;

public abstract class X509CertificateExtension
{
    public byte[] RawData { get; internal set; } = [];

    internal static string EncodeUri(string input)
    {
        ArgumentNullException.ThrowIfNull(input);

        return input.StartsWith("http://") || input.StartsWith("https://") || input.StartsWith("ldap://")
            ? input.Replace(" ", "%20")
            : input;
    }
}