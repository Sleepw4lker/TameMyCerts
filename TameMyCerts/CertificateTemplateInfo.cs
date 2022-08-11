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

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace TameMyCerts
{
    public class CertificateTemplateInfo
    {
        private static readonly Regex IsLegacyTemplate = new Regex(@"^[a-zA-z]*$");
        private readonly object _lockObject = new object();
        private readonly int _refreshInterval;
        private DateTime _lastRefreshTime = new DateTime(1970, 1, 1);
        private List<Template> _templateInfoList;

        public CertificateTemplateInfo(int refreshInterval = 5)
        {
            _refreshInterval = refreshInterval;
        }

        private void UpdateTemplateInfoList()
        {
            var newObjects = new List<Template>();
            var machineBaseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            var templateBaseKey =
                machineBaseKey.OpenSubKey("SOFTWARE\\Microsoft\\Cryptography\\CertificateTemplateCache");

            if (templateBaseKey == null)
            {
                return;
            }

            var templateNames = templateBaseKey.GetSubKeyNames();

            foreach (var templateName in templateNames)
            {
                var templateSubKey = templateBaseKey.OpenSubKey(templateName);

                if (templateSubKey == null)
                {
                    continue;
                }

                var nameFlags = Convert.ToInt32(templateSubKey.GetValue("msPKI-Certificate-Name-Flag"));

                newObjects.Add(new Template
                {
                    Name = templateName,
                    Oid = ((string[]) templateSubKey.GetValue("msPKI-Cert-Template-OID"))[0],
                    EnrolleeSuppliesSubject = (CertCa.CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT & nameFlags) ==
                                              CertCa.CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
                });
            }

            _lastRefreshTime = DateTime.Now;
            _templateInfoList = newObjects;
        }

        public Template GetTemplate(string identifier)
        {
            lock (_lockObject)
            {
                if (_lastRefreshTime.AddMinutes(_refreshInterval) < DateTime.Now)
                {
                    UpdateTemplateInfoList();
                }
            }

            // V1 templates are identified by their object name (containing only letters)
            // V2 and newer templates are identified by an OID (numbers separated by dots)

            return IsLegacyTemplate.IsMatch(identifier)
                ? _templateInfoList.FirstOrDefault(x => x.Name == identifier)
                : _templateInfoList.FirstOrDefault(x => x.Oid == identifier);
        }

        public class Template
        {
            public string Name { get; set; }
            public string Oid { get; set; }
            public bool EnrolleeSuppliesSubject { get; set; }
        }
    }
}