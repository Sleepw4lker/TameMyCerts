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

using CERTCLILib;
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using TameMyCerts.ClassExtensions;
using TameMyCerts.Enums;

namespace TameMyCerts.Models;

internal class CertificateAuthorityConfiguration
{
    private const string CONFIG_ROOT =
        "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration";

    public CertificateAuthorityConfiguration(string strConfig, string appName)
    {
        var serverPolicy = new CCertServerPolicy();
        serverPolicy.SetContext(0);

        CaCertIndex = serverPolicy.GetLongCertificatePropertyOrDefault("CertCount") - 1;
        CrlIndex = serverPolicy.GetLongCertificatePropertyOrDefault($"CRLIndex.{CaCertIndex}");
        SanitizedCaName = serverPolicy.GetStringCertificatePropertyOrDefault("SanitizedShortName");

        // TODO: Use registry only for the properties that cannot ready directly from CCertServerPolicy

        var serverRoot = $"{CONFIG_ROOT}\\{strConfig}";
        var policyModulesRoot = $"{serverRoot}\\PolicyModules";

        var activePolicyModuleName = (string)Registry.GetValue(policyModulesRoot, "Active", appName);
        var activePolicyModuleRoot = $"{policyModulesRoot}\\{activePolicyModuleName}";

        LogLevel = (int)Registry.GetValue($"{serverRoot}", "LogLevel", CertSrv.CERTLOG_WARNING);
        Type = (CaType)(int)Registry.GetValue($"{serverRoot}", "CAType", (int)CaType.ENUM_STANDALONE_ROOTCA);
        ServerDnsName = (string)Registry.GetValue(serverRoot, "CAServerName", string.Empty);
        CaName = (string)Registry.GetValue(serverRoot, "CommonName", string.Empty);
        ConfigurationContainer = (string)Registry.GetValue(serverRoot, "DSConfigDN", string.Empty);
        PolicyDirectory = (string)Registry.GetValue(activePolicyModuleRoot, "PolicyDirectory", Path.GetTempPath());
        EditFlags = (EditFlag)(int)Registry.GetValue(activePolicyModuleRoot, "EditFlags", 0);
        TmcFlags = (TmcFlag)(int)Registry.GetValue(activePolicyModuleRoot, "TmcFlags", 0);

        _strConfig  = strConfig;
        _appName    = appName;
    }

    // TODO: Merge the two testing constructors, move default values to Unit test project
    // To inject Unit tests
    public CertificateAuthorityConfiguration(EditFlag editFlags)
    {
        LogLevel = 3;
        Type = CaType.ENUM_ENTERPRISE_SUBCA;
        PolicyDirectory = string.Empty;
        EditFlags = editFlags;
    }

    // To inject Unit tests
    public CertificateAuthorityConfiguration(int caCertIndex, int crlIndex, string caName, string sanitizedCaName,
        string serverShortName, string serverDnsName, string configurationContainer)
    {
        LogLevel = 3;
        Type = CaType.ENUM_ENTERPRISE_SUBCA;
        PolicyDirectory = string.Empty;
        EditFlags = 0;
        CaCertIndex = caCertIndex;
        CrlIndex = crlIndex;
        CaName = caName;
        SanitizedCaName = sanitizedCaName;
        ServerShortName = serverShortName;
        ServerDnsName = serverDnsName;
        ConfigurationContainer = configurationContainer;
    }

    public string PolicyDirectory { get; }
    public EditFlag EditFlags { get; }
    public TmcFlag TmcFlags { get; }
    public CaType Type { get; }
    public bool IsSupportedCaType => Type == CaType.ENUM_ENTERPRISE_ROOTCA || Type == CaType.ENUM_ENTERPRISE_SUBCA;
    public int LogLevel { get; }
    private string ServerShortName { get; } = Environment.MachineName;
    private string ServerDnsName { get; }
    private string CaName { get; }
    private string SanitizedCaName { get; }
    private string ConfigurationContainer { get; }
    private string CrlNameSuffix => CrlIndex == 0 ? string.Empty : $"({CrlIndex})";
    private string CertificateName => CaCertIndex == 0 ? string.Empty : $"({CaCertIndex})";
    private int CaCertIndex { get; }
    private int CrlIndex { get; }

    private readonly string _strConfig;

    private readonly string _appName;

    public string ReplaceTokenValues(string input)
    {
        return input
            .Replace("%11", "?cACertificate?base?objectClass=certificationAuthority")
            .Replace("%10", "?certificateRevocationList?base?objectClass=cRLDistributionPoint")
            .Replace("%9", string.Empty) // not relevant as we issue only certificates, not CRLs
            .Replace("%8", CrlNameSuffix)
            .Replace("%7", SanitizedCaName)
            .Replace("%6", ConfigurationContainer)
            .Replace("%4", CertificateName)
            .Replace("%3", CaName)
            .Replace("%2", ServerShortName)
            .Replace("%1", ServerDnsName);
    }

    // Read blacklist of OID
    internal HashSet<string> ReadBlockedOids()
    {
        var policyModulesRoot = $"{CONFIG_ROOT}\\{_strConfig}\\PolicyModules";
        var activePolicyModuleName = (string)Registry.GetValue(policyModulesRoot, "Active", _appName);
        var activePolicyModuleRoot = $"{policyModulesRoot}\\{activePolicyModuleName}";

        var raw = Registry.GetValue(activePolicyModuleRoot, "BlockedOIDs", null);
        if (raw == null) return new HashSet<string>();

        IEnumerable<string> items = raw switch
        {
            string s => s.Split(new[] { ',', ';', '\r', '\n', '\t', ' ' }, StringSplitOptions.RemoveEmptyEntries),
            string[] a => a,
            _ => Array.Empty<string>()
        };

        return items
            .Select(x => x.Trim())
            .Where(x => x.Length > 0)
            .ToHashSet();
    }
    
}