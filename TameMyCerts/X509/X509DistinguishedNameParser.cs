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
using TameMyCerts.Models;

namespace TameMyCerts.X509;

public static class X509DistinguishedNameParser
{
    /// <summary>
    ///     Parses an ASN.1 encoded X.509 Subject Distinguished Name.
    /// </summary>
    public static List<KeyValuePair<string, string>> Parse(byte[] encodedSubjectDn)
    {
        var result = new List<KeyValuePair<string, string>>();

        if (encodedSubjectDn is null || encodedSubjectDn.Length == 0)
        {
            return result;
        }

        var reader = new AsnReader(encodedSubjectDn, AsnEncodingRules.DER);

        // Name ::= SEQUENCE OF RelativeDistinguishedName
        var nameSequence = reader.ReadSequence();

        while (nameSequence.HasData)
        {
            // RelativeDistinguishedName ::= SET OF AttributeTypeAndValue
            var rdnSet = nameSequence.ReadSetOf();

            while (rdnSet.HasData)
            {
                // AttributeTypeAndValue ::= SEQUENCE { type OBJECT IDENTIFIER, value ANY }
                var atvSequence = rdnSet.ReadSequence();

                var oidValue = atvSequence.ReadObjectIdentifier();

                result.Add(new KeyValuePair<string, string>
                (
                    RdnTypes.OidToLongName.TryGetValue(oidValue, out var value)
                        ? value
                        : $"OID.{oidValue}",
                    ReadAsn1ValueAsString(atvSequence)
                ));

                atvSequence.ThrowIfNotEmpty();
            }
        }

        reader.ThrowIfNotEmpty();
        return result;
    }

    private static string ReadAsn1ValueAsString(AsnReader reader)
    {
        var tag = reader.PeekTag();

        return tag.TagValue switch
        {
            (int)UniversalTagNumber.UTF8String =>
                reader.ReadCharacterString(UniversalTagNumber.UTF8String),

            (int)UniversalTagNumber.PrintableString =>
                reader.ReadCharacterString(UniversalTagNumber.PrintableString),

            (int)UniversalTagNumber.IA5String =>
                reader.ReadCharacterString(UniversalTagNumber.IA5String),

            (int)UniversalTagNumber.BMPString =>
                reader.ReadCharacterString(UniversalTagNumber.BMPString),

            (int)UniversalTagNumber.T61String =>
                reader.ReadCharacterString(UniversalTagNumber.T61String),

            (int)UniversalTagNumber.UniversalString =>
                reader.ReadCharacterString(UniversalTagNumber.UniversalString),

            // Read encoded value and return hex if we don't recognize the type
            _ => Convert.ToHexString(reader.ReadEncodedValue().Span)
        };
    }
}