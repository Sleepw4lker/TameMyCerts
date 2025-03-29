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

    public static readonly Dictionary<string, string> NameProperty = new()
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

    public static readonly Dictionary<string, int> LengthConstraint = new()
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

    public static readonly Dictionary<string, string> ShortToLongName = new()
    {
        { "C", Country },
        { "CN", CommonName },
        { "DC", DomainComponent },
        { "E", Email },
        { "L", Locality },
        { "O", Organization },
        { "OU", OrgUnit },
        { "S", State },
        { "G", GivenName },
        { "I", Initials },
        { "SN", SurName },
        { "STREET", StreetAddress },
        { "T", Title },
        { "OID.1.2.840.113549.1.9.2", UnstructuredName },
        { "OID.1.2.840.113549.1.9.8", UnstructuredAddress },
        { "SERIALNUMBER", DeviceSerialNumber },
        { "POSTALCODE", "postalCode" },
        { "DESCRIPTION", "description" },
        { "POBOX", "postOfficeBox" },
        { "PHONE", "telephoneNumber" }
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