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
using System.Linq;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using TameMyCerts.Enums;

namespace TameMyCerts.Models;

internal class CertificateTemplateCache
{
    private static readonly Regex IsLegacyTemplate = new(@"^[a-zA-z]*$");
    private readonly object _lockObject = new();
    private readonly int _refreshInterval;

    // TODO: Can't this be a dictionary?
    private List<CertificateTemplate> _certificateTemplateList;
    private DateTime _lastRefreshTime = new(1970, 1, 1);

    public CertificateTemplateCache(int refreshInterval = 5)
    {
        _refreshInterval = refreshInterval;
    }

    private void UpdateCache()
    {
        var machineBaseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        var templateBaseKey =
            machineBaseKey.OpenSubKey("SOFTWARE\\Microsoft\\Cryptography\\CertificateTemplateCache");

        if (templateBaseKey == null)
        {
            return;
        }

        var templateNames = templateBaseKey.GetSubKeyNames();

        var newObjects = (from templateName in templateNames
            let templateSubKey = templateBaseKey.OpenSubKey(templateName)
            where templateSubKey != null
            let flags = Convert.ToInt32(templateSubKey.GetValue("Flags"))
            let certificateNameFlags = Convert.ToInt32(templateSubKey.GetValue("msPKI-Certificate-Name-Flag"))
            let raApplicationPolicies = (string[])templateSubKey.GetValue("msPKI-RA-Application-Policies")
            select new CertificateTemplate
            (
                templateName, ((SubjectNameFlag)certificateNameFlags).HasFlag(SubjectNameFlag
                    .CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT), raApplicationPolicies.Length > 0
                    ? GetKeyAlgorithm(raApplicationPolicies[0])
                    : KeyAlgorithmType.RSA, !((GeneralFlag)flags).HasFlag(GeneralFlag.CT_FLAG_MACHINE_TYPE),
                ((string[])templateSubKey.GetValue("msPKI-Cert-Template-OID"))[0])).ToList();

        _lastRefreshTime = DateTime.Now;
        _certificateTemplateList = newObjects;
    }

    public CertificateTemplate GetCertificateTemplate(string identifier)
    {
        lock (_lockObject)
        {
            if (_lastRefreshTime.AddMinutes(_refreshInterval) < DateTime.Now)
            {
                UpdateCache();
            }
        }

        // V1 templates are identified by their object name (containing only letters)
        // V2 and newer templates are identified by an OID (numbers separated by dots)
        return IsLegacyTemplate.IsMatch(identifier)
            ? _certificateTemplateList.FirstOrDefault(template => template.Name == identifier)
            : _certificateTemplateList.FirstOrDefault(template => template.Oid == identifier);
    }

    private static KeyAlgorithmType GetKeyAlgorithm(string keyAlgorithmString)
    {
        foreach (var algorithmName in Enum.GetNames(typeof(KeyAlgorithmType)))
        {
            if (keyAlgorithmString.Contains($"msPKI-Asymmetric-Algorithm`PZPWSTR`{algorithmName}`"))
            {
                return (KeyAlgorithmType)Enum.Parse(typeof(KeyAlgorithmType), algorithmName);
            }
        }

        return KeyAlgorithmType.RSA;
    }
}