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
using System.IO;
using System.Linq;
using System.Threading;

namespace TameMyCerts.Models;

internal class CertificateRequestPolicyCache
{
    private readonly Dictionary<string, CertificateRequestPolicyCacheEntry> _cache = new();
    private readonly Lock _lockObject = new();
    private readonly string _policyDirectory;
    public bool PolicyDirectoryExists => Directory.Exists(_policyDirectory);

    public CertificateRequestPolicyCache(string policyDirectory)
    {
        _policyDirectory = policyDirectory;
    }

    public CertificateRequestPolicyCacheEntry GetCertificateRequestPolicy(string certificateTemplate)
    {
        var policyFileName = Path.Combine(_policyDirectory, RemoveInvalidFileNameChars($"{certificateTemplate}.xml"));

        lock (_lockObject)
        {
            if (!File.Exists(policyFileName))
            {
                _cache.Remove(certificateTemplate);
                return null;
            }

            if (_cache.TryGetValue(certificateTemplate, out var cacheEntry) &&
                cacheEntry.LastUpdateUtc.UtcDateTime >= File.GetLastWriteTimeUtc(policyFileName))
            {
                return cacheEntry;
            }

            var newCacheEntry = new CertificateRequestPolicyCacheEntry(policyFileName);

            _cache[certificateTemplate] = newCacheEntry;

            return newCacheEntry;
        }
    }

    private static string RemoveInvalidFileNameChars(string fileName)
    {
        return Path.GetInvalidFileNameChars()
            .Aggregate(fileName, (current, c) => current.Replace(c.ToString(), string.Empty));
    }
}