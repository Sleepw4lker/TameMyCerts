// Copyright 2021-2023 Uwe Gradenegger <uwe@gradenegger.eu>

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

namespace TameMyCerts.Models;

internal class CertificateRequestPolicyCacheEntry
{
    public CertificateRequestPolicyCacheEntry(string fileName)
    {
        try
        {
            CertificateRequestPolicy = CertificateRequestPolicy.LoadFromFile(fileName);
            ETWLogger.Log.TMC_91_Policy_Read(fileName, CertificateRequestPolicy.SaveToString());
        }
        catch (Exception ex)
        {
            ErrorMessage = ex.InnerException != null
                ? $"{ex.Message} {ex.InnerException.Message}"
                : ex.Message;
        }

        LastUpdate = DateTimeOffset.Now;
    }

    public CertificateRequestPolicy CertificateRequestPolicy { get; }
    public DateTimeOffset LastUpdate { get; }
    public string ErrorMessage { get; } = string.Empty;
}