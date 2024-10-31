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

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace TameMyCerts.X509;

public class X509CertificateExtensionAuthorityInformationAccess : X509CertificateExtension
{
    private readonly List<KeyValuePair<Uri, bool>> _uris = new();

    public void AddUniformResourceIdentifier(string uri, bool isOcsp = false)
    {
        if (Uri.TryCreate(uri, UriKind.Absolute, out var uriObject))
        {
            AddUniformResourceIdentifier(uriObject, isOcsp);
        }
    }

    public void AddUniformResourceIdentifier(Uri uri, bool isOcsp = false)
    {
        _uris.Add(new KeyValuePair<Uri, bool>(uri, isOcsp));
    }

    public void InitializeEncode(bool encodeUris = false)
    {
        var result = Array.Empty<byte>();

        result = (from keyValuePair in _uris
            let node = keyValuePair.Value
                ? new byte[] { 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01 } // 1.3.6.1.5.5.7.48.1
                : new byte[] { 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02 } // 1.3.6.1.5.5.7.48.2
            let uri = keyValuePair.Key.ToString()
            select node.Concat(Asn1BuildNode(0x86, Encoding.ASCII.GetBytes(encodeUris ? EncodeUri(uri) : uri)))
                .ToArray()).Aggregate(result,
            (current, node) => current.Concat(Asn1BuildNode(0x30, node)).ToArray());

        RawData = Asn1BuildNode(0x30, result);
    }
}