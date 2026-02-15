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

namespace TameMyCerts.Models;

internal static class RdnTypes
{
    public const string Email = "emailAddress";
    public const string CommonName = "commonName";
    public const string Organization = "organizationName";
    public const string OrgUnit = "organizationalUnitName";
    public const string Locality = "localityName";
    public const string State = "stateOrProvinceName";
    public const string Country = "countryName";
    public const string Title = "title";
    public const string GivenName = "givenName";
    public const string Initials = "initials";
    public const string SurName = "surname";
    public const string StreetAddress = "streetAddress";
    public const string UnstructuredName = "unstructuredName";
    public const string UnstructuredAddress = "unstructuredAddress";
    public const string DeviceSerialNumber = "serialNumber";
    public const string DomainComponent = "domainComponent";

    public static readonly IReadOnlyDictionary<string, string> NameProperty =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            { Email, "Subject.Email" },
            { CommonName, "Subject.CommonName" },
            { Organization, "Subject.Organization" },
            { OrgUnit, "Subject.OrgUnit" },
            { Locality, "Subject.Locality" },
            { State, "Subject.State" },
            { Country, "Subject.Country" },
            { Title, "Subject.Title" },
            { GivenName, "Subject.GivenName" },
            { Initials, "Subject.Initials" },
            { SurName, "Subject.SurName" },
            { StreetAddress, "Subject.StreetAddress" },
            { UnstructuredName, "Subject.UnstructuredName" },
            { UnstructuredAddress, "Subject.UnstructuredAddress" },
            { DeviceSerialNumber, "Subject.DeviceSerialNumber" },
            { DomainComponent, "Subject.DomainComponent" }
        };

    public static readonly IReadOnlyDictionary<string, int> LengthConstraint =
        new Dictionary<string, int>(StringComparer.Ordinal)
        {
            { Email, 128 },
            { CommonName, 64 },
            { Organization, 64 },
            { OrgUnit, 64 },
            { Locality, 128 },
            { State, 128 },
            { Country, 2 },
            { Title, 64 },
            { GivenName, 16 },
            { Initials, 5 },
            { SurName, 40 },
            { StreetAddress, 30 },
            { UnstructuredName, 1024 },
            { UnstructuredAddress, 1024 },
            { DeviceSerialNumber, 1024 },
            { DomainComponent, 128 }
        };

    public static readonly IReadOnlyDictionary<string, string> OidToLongName =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            // X.520 core
            ["2.5.4.6"] = Country,
            ["2.5.4.3"] = CommonName,
            ["2.5.4.7"] = Locality,
            ["2.5.4.10"] = Organization,
            ["2.5.4.11"] = OrgUnit,
            ["2.5.4.8"] = State,
            ["2.5.4.42"] = GivenName,
            ["2.5.4.43"] = Initials,
            ["2.5.4.4"] = SurName,
            ["2.5.4.9"] = StreetAddress,
            ["2.5.4.12"] = Title,
            ["2.5.4.5"] = DeviceSerialNumber,

            ["2.5.4.13"] = "description",
            ["2.5.4.20"] = "telephoneNumber",
            ["2.5.4.18"] = "postOfficeBox",
            ["2.5.4.17"] = "postalCode",

            // PKCS #9
            ["1.2.840.113549.1.9.1"] = Email,
            ["1.2.840.113549.1.9.2"] = UnstructuredName,
            ["1.2.840.113549.1.9.8"] = UnstructuredAddress,

            // Domain Component (RFC 4519)
            ["0.9.2342.19200300.100.1.25"] = DomainComponent
        };

    public static List<string> ToList()
    {
        return
        [
            Email,
            CommonName,
            Organization,
            OrgUnit,
            Locality,
            State,
            Country,
            Title,
            GivenName,
            Initials,
            SurName,
            StreetAddress,
            UnstructuredName,
            UnstructuredAddress,
            DeviceSerialNumber,
            DomainComponent
        ];
    }
}