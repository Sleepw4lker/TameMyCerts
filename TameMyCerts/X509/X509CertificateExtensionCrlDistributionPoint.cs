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
using System.Collections.Generic;
using System.Formats.Asn1;

namespace TameMyCerts.X509;

public class X509CertificateExtensionCrlDistributionPoint : X509CertificateExtension
{
    private readonly List<Uri> _uris = [];

    public void AddUniformResourceIdentifier(string uri)
    {
        ArgumentNullException.ThrowIfNull(uri);

        if (Uri.TryCreate(uri, UriKind.Absolute, out var uriObject))
        {
            AddUniformResourceIdentifier(uriObject);
        }
    }

    public void AddUniformResourceIdentifier(Uri uri)
    {
        ArgumentNullException.ThrowIfNull(uri);

        if (!_uris.Contains(uri))
        {
            _uris.Add(uri);
        }
    }

    public void InitializeEncode(bool encodeUris = false)
    {
        var asnWriter = new AsnWriter(AsnEncodingRules.DER);

        using (asnWriter.PushSequence())
        {
            using (asnWriter.PushSequence())
            {
                using (asnWriter.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
                {
                    using (asnWriter.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
                    {
                        foreach (var uri in _uris)
                        {
                            asnWriter.WriteCharacterString(UniversalTagNumber.IA5String,
                                encodeUris ? EncodeUri(uri.ToString()) : uri.ToString(),
                                new Asn1Tag(TagClass.ContextSpecific, 6));
                        }
                    }
                }
            }
        }

        RawData = asnWriter.Encode();
    }
}