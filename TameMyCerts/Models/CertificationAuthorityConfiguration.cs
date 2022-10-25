// Copyright 2021 Uwe Gradenegger <uwe@gradenegger.eu>

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

using System.IO;
using Microsoft.Win32;
using TameMyCerts.Enums;

namespace TameMyCerts.Models
{
    public class CertificationAuthorityConfiguration
    {
        private const string CONFIG_ROOT =
            "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration";

        public CertificationAuthorityConfiguration(string strConfig, string appName)
        {
            var policyModulesRoot = $"{CONFIG_ROOT}\\{strConfig}\\PolicyModules";

            var activePolicyModuleName = (string) Registry.GetValue(policyModulesRoot, "Active", appName);
            var activePolicyModuleRoot = $"{policyModulesRoot}\\{activePolicyModuleName}";

            LogLevel = (int) Registry.GetValue($"{CONFIG_ROOT}\\{strConfig}", "LogLevel", CertSrv.CERTLOG_WARNING);
            Type = (CaType) (int) Registry.GetValue($"{CONFIG_ROOT}\\{strConfig}", "CAType",
                (int) CaType.ENUM_STANDALONE_ROOTCA);
            PolicyDirectory = (string) Registry.GetValue(activePolicyModuleRoot, "PolicyDirectory", Path.GetTempPath());
            EditFlags = (EditFlag) (int) Registry.GetValue(activePolicyModuleRoot, "EditFlags", 0);
            IsSupportedCaType = Type == CaType.ENUM_ENTERPRISE_ROOTCA || Type == CaType.ENUM_ENTERPRISE_SUBCA;
        }

        // To inject Unit tests
        public CertificationAuthorityConfiguration(EditFlag editFlags)
        {
            LogLevel = 3;
            Type = CaType.ENUM_ENTERPRISE_SUBCA;
            PolicyDirectory = string.Empty;
            EditFlags = editFlags;
            IsSupportedCaType = true;
        }

        public string PolicyDirectory { get; }
        public EditFlag EditFlags { get; }
        public CaType Type { get; }
        public bool IsSupportedCaType { get; }
        public int LogLevel { get; }
    }
}