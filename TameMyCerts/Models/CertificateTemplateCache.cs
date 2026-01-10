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
using System.Threading;
using Microsoft.Win32;
using TameMyCerts.Enums;

namespace TameMyCerts.Models;

internal sealed class CertificateTemplateCache
{
    private readonly Lock _lock = new();
    private readonly int _refreshInterval;

    private volatile IReadOnlyDictionary<string, CertificateTemplate> _cache =
        new Dictionary<string, CertificateTemplate>();

    private long _nextRefreshTicks = long.MinValue;

    public CertificateTemplateCache(int refreshInterval = 5)
    {
        _refreshInterval = refreshInterval;
    }

    private void RefreshCache()
    {
        lock (_lock)
        {
            if (IsCacheStillValid())
            {
                return;
            }

            using var machineBaseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var templateBaseKey =
                machineBaseKey.OpenSubKey("SOFTWARE\\Microsoft\\Cryptography\\CertificateTemplateCache");

            if (templateBaseKey == null || templateBaseKey.SubKeyCount == 0)
            {
                // There might be rare cases where the key is deleted and rebuilt by the AutoEnrollment process at the 
                // very time we try to refresh the cache. In this case, we skip one interval and retry next time.
                SetNextRefreshTime();
                return;
            }

            var newCache = new Dictionary<string, CertificateTemplate>(StringComparer.Ordinal);

            foreach (var templateName in templateBaseKey.GetSubKeyNames())
            {
                using var templateSubKey = templateBaseKey.OpenSubKey(templateName);

                if (templateSubKey == null)
                {
                    continue;
                }

                var flags = (GeneralFlag)Convert.ToInt32(templateSubKey.GetValue("Flags"));

                var certificateNameFlags =
                    (SubjectNameFlag)Convert.ToInt32(templateSubKey.GetValue("msPKI-Certificate-Name-Flag"));

                var raApplicationPolicies =
                    templateSubKey.GetValue("msPKI-RA-Application-Policies") as string[] ?? [];

                var templateOid =
                    (templateSubKey.GetValue("msPKI-Cert-Template-OID") as string[] ?? [])[0];

                var schemaVersion = (int)templateSubKey.GetValue("msPKI-Template-Schema-Version", 1);

                var identifier = schemaVersion > 1 ? templateOid : templateName;

                var certificateTemplate = new CertificateTemplate(
                    templateName,
                    certificateNameFlags.HasFlag(SubjectNameFlag.CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT),
                    raApplicationPolicies.Length > 0 ? GetKeyAlgorithm(raApplicationPolicies[0]) : KeyAlgorithmType.RSA,
                    !flags.HasFlag(GeneralFlag.CT_FLAG_MACHINE_TYPE),
                    templateOid);

                newCache[identifier] = certificateTemplate;
            }

            _cache = newCache;

            SetNextRefreshTime();
        }
    }

    public CertificateTemplate GetCertificateTemplate(string identifier)
    {
        if (!IsCacheStillValid())
        {
            RefreshCache();
        }

        var snapshot = _cache;

        return snapshot.GetValueOrDefault(identifier);
    }

    private void SetNextRefreshTime()
    {
        var next = DateTimeOffset.UtcNow.AddMinutes(_refreshInterval).AddSeconds(Random.Shared.Next(0, 60)).UtcTicks;

        Volatile.Write(ref _nextRefreshTicks, next);
    }

    private bool IsCacheStillValid()
    {
        var now = DateTimeOffset.UtcNow.UtcTicks;

        // Volatile read is intentional: lock-free fast path for cache validity
        return Volatile.Read(ref _nextRefreshTicks) >= now;
    }

    private static KeyAlgorithmType GetKeyAlgorithm(string keyAlgorithmString)
    {
        foreach (var algorithmName in Enum.GetNames<KeyAlgorithmType>())
        {
            if (keyAlgorithmString.Contains($"msPKI-Asymmetric-Algorithm`PZPWSTR`{algorithmName}`"))
            {
                return Enum.Parse<KeyAlgorithmType>(algorithmName);
            }
        }

        return KeyAlgorithmType.RSA;
    }
}