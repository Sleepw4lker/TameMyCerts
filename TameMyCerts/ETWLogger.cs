// Copyright 2021-2025 Uwe Gradenegger <info@gradenegger.eu>
// Copyright 2024 Oscar Virot <virot@virot.com>

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

using System.Diagnostics.Tracing;

namespace TameMyCerts;

[EventSource(Name = "TameMyCerts-TameMyCerts-Policy", LocalizationResources = "TameMyCerts.LocalizedStrings")]
// This needs to be named Company-Product-Component, it is hardcoded into EventViewer.
public sealed class ETWLogger : EventSource
{
    public static ETWLogger Log = new();

    public static class Tasks
    {
        public const EventTask None = (EventTask)1;
        public const EventTask TameMyCerts = (EventTask)2;
        public const EventTask YubikeyValidator = (EventTask)10;
        public const EventTask XMLParser = (EventTask)11;
        public const EventTask FileSystemStorer = (EventTask)12;
        public const EventTask CertificateContentValidator = (EventTask)13;
    }

    #region Tame My Certs events 1-299

    [Event(1, Level = EventLevel.Informational, Channel = EventChannel.Admin, Task = Tasks.TameMyCerts,
        Keywords = EventKeywords.None)]
    public void TMC_1_PolicyModule_Success_Initiated(string policyModule, string version)
    {
        if (IsEnabled())
        {
            WriteEvent(1, policyModule, version);
        }
    }

    [Event(2, Level = EventLevel.Error, Channel = EventChannel.Admin, Task = Tasks.TameMyCerts,
        Keywords = EventKeywords.None)]
    public void TMC_2_PolicyModule_Failed_Initiated(string exception)
    {
        if (IsEnabled())
        {
            WriteEvent(2, exception);
        }
    }

    [Event(4, Level = EventLevel.Error, Channel = EventChannel.Admin, Task = Tasks.TameMyCerts,
        Keywords = EventKeywords.None)]
    public void TMC_4_PolicyModule_Default_Shutdown_Failed(string exception)
    {
        if (IsEnabled())
        {
            WriteEvent(4, exception);
        }
    }

    [Event(5, Level = EventLevel.Informational, Channel = EventChannel.Analytic, Task = Tasks.TameMyCerts,
        Keywords = EventKeywords.None)]
    public void TMC_5_Analytical_Audit_only_Deny(int requestId, string template, string reason)
    {
        if (IsEnabled())
        {
            WriteEvent(5, requestId, template, reason);
        }
    }

    [Event(6, Level = EventLevel.Informational, Channel = EventChannel.Admin, Task = Tasks.TameMyCerts,
        Keywords = EventKeywords.None)]
    public void TMC_6_Deny_Issuing_Request(int requestId, string template, string reason)
    {
        if (IsEnabled())
        {
            WriteEvent(6, requestId, template, reason);
        }
    }

    [Event(12, Level = EventLevel.Informational, Channel = EventChannel.Admin, Task = Tasks.TameMyCerts,
        Keywords = EventKeywords.None)]
    public void TMC_12_Success_Issued(int requestId, string template)
    {
        if (IsEnabled())
        {
            WriteEvent(12, requestId, template);
        }
    }

    [Event(13, Level = EventLevel.Informational, Channel = EventChannel.Admin, Task = Tasks.TameMyCerts,
        Keywords = EventKeywords.None)]
    public void TMC_13_Success_Pending(int requestId, string template)
    {
        if (IsEnabled())
        {
            WriteEvent(13, requestId, template);
        }
    }

    [Event(91, Level = EventLevel.Informational, Channel = EventChannel.Debug, Task = Tasks.XMLParser,
        Keywords = EventKeywords.None)]
    public void TMC_91_Policy_Read(string templateName, string policy)
    {
        if (IsEnabled())
        {
            WriteEvent(91, templateName, policy);
        }
    }

    [Event(92, Level = EventLevel.Critical, Channel = EventChannel.Admin, Task = Tasks.XMLParser,
        Keywords = EventKeywords.None)]
    public void TMC_92_Policy_Unknown_XML_Element(string elementName, int lineNumber, int linePosition)
    {
        if (IsEnabled())
        {
            WriteEvent(92, elementName, lineNumber, linePosition);
        }
    }

    [Event(93, Level = EventLevel.Critical, Channel = EventChannel.Admin, Task = Tasks.XMLParser,
        Keywords = EventKeywords.None)]
    public void TMC_93_Policy_Unknown_XML_Attribute(string attributeName, string attributeValue, int lineNumber,
        int linePosition)
    {
        if (IsEnabled())
        {
            WriteEvent(93, attributeName, attributeValue, lineNumber, linePosition);
        }
    }

    [Event(94, Level = EventLevel.Critical, Channel = EventChannel.Admin, Task = Tasks.XMLParser,
        Keywords = EventKeywords.None)]
    public void TMC_94_XML_Parsing_error(string filename, string error)
    {
        if (IsEnabled())
        {
            WriteEvent(94, filename, error);
        }
    }

    #endregion

    #region Yubico Validator events 4201-4399

    [Event(4201, Level = EventLevel.Warning, Channel = EventChannel.Operational, Task = Tasks.YubikeyValidator,
        Keywords = EventKeywords.None)]
    public void YKVal_4201_Denied_by_Policy(int requestId, string denyingPolicy)
    {
        if (IsEnabled())
        {
            WriteEvent(4201, requestId, denyingPolicy);
        }
    }

    [Event(4202, Level = EventLevel.Warning, Channel = EventChannel.Operational, Task = Tasks.YubikeyValidator,
        Keywords = EventKeywords.None)]
    public void YKVal_4202_Denied_by_Policy(int requestId)
    {
        if (IsEnabled())
        {
            WriteEvent(4202, requestId);
        }
    }

    [Event(4203, Level = EventLevel.Warning, Channel = EventChannel.Operational, Task = Tasks.YubikeyValidator,
        Keywords = EventKeywords.None)]
    public void YKVal_4203_Denied_due_to_no_matching_policy_default_deny(int requestId)
    {
        if (IsEnabled())
        {
            WriteEvent(4203, requestId);
        }
    }

    [Event(4204, Level = EventLevel.Verbose, Channel = EventChannel.Operational, Task = Tasks.YubikeyValidator,
        Keywords = EventKeywords.None)]
    public void YKVal_4204_Matching_policy(int requestId, string policy, string yubiKey)
    {
        if (IsEnabled())
        {
            WriteEvent(4204, requestId, policy, yubiKey);
        }
    }

    [Event(4205, Level = EventLevel.Error, Channel = EventChannel.Operational, Task = Tasks.YubikeyValidator,
        Keywords = EventKeywords.None)]
    public void YKVal_4205_Failed_to_extract_Yubikey_Attestation(int requestId)
    {
        if (IsEnabled())
        {
            WriteEvent(4205, requestId);
        }
    }

    [Event(4206, Level = EventLevel.Warning, Channel = EventChannel.Debug, Task = Tasks.YubikeyValidator,
        Keywords = EventKeywords.None)]
    public void YKVal_4206_Debug_failed_to_match_policy(int requestId, string policy)
    {
        if (IsEnabled())
        {
            WriteEvent(4206, requestId, policy);
        }
    }

    [Event(4207, Level = EventLevel.Error, Channel = EventChannel.Operational, Task = Tasks.YubikeyValidator,
        Keywords = EventKeywords.None)]
    public void YKVal_4207_Yubikey_Attestation_Mismatch_with_CSR(int requestId)
    {
        if (IsEnabled())
        {
            WriteEvent(4207, requestId);
        }
    }

    [Event(4208, Level = EventLevel.Error, Channel = EventChannel.Operational, Task = Tasks.YubikeyValidator,
        Keywords = EventKeywords.None)]
    public void YKVal_4208_Yubikey_Attestation_Failed_to_build(int requestId)
    {
        if (IsEnabled())
        {
            WriteEvent(4208, requestId);
        }
    }

    [Event(4209, Level = EventLevel.Informational, Channel = EventChannel.Debug, Task = Tasks.YubikeyValidator,
        Keywords = EventKeywords.None)]
    public void YKVal_4209_Found_Attestation_Location(int requestId, string attestationLocation)
    {
        if (IsEnabled())
        {
            WriteEvent(4209, requestId, attestationLocation);
        }
    }

    #endregion

    #region Certificate Content Validator events 4601-4799

    /*
    [Event(4601, Level = EventLevel.Informational, Channel = EventChannel.Operational,
        Task = Tasks.CertificateContentValidator, Keywords = EventKeywords.None)]
    public void CCVal_4601_(string denyingPolicy, int requestId)
    {
        if (IsEnabled())
        {
            WriteEvent(4601, denyingPolicy, requestId);
        }
    }
    */

    [Event(4651, Level = EventLevel.Verbose, Channel = EventChannel.Debug, Task = Tasks.CertificateContentValidator,
        Keywords = EventKeywords.None)]
    public void CCVal_4651_SAN_Already_Exists(int requestId, string subjectAltName, string currentValue,
        string ignoredValue)
    {
        if (IsEnabled())
        {
            WriteEvent(4651, requestId, subjectAltName, currentValue, ignoredValue);
        }
    }

    [Event(4652, Level = EventLevel.Verbose, Channel = EventChannel.Debug, Task = Tasks.CertificateContentValidator,
        Keywords = EventKeywords.None)]
    public void CCVal_4652_SAN_Added(int requestId, string subjectAltName, string addedValue)
    {
        if (IsEnabled())
        {
            WriteEvent(4652, requestId, subjectAltName, addedValue);
        }
    }

    [Event(4653, Level = EventLevel.Verbose, Channel = EventChannel.Debug, Task = Tasks.CertificateContentValidator,
        Keywords = EventKeywords.None)]
    public void CCVal_4653_SAN_Failed_to_add(int requestId, string subjectAltName, string ignoredValue)
    {
        if (IsEnabled())
        {
            WriteEvent(4653, requestId, subjectAltName, ignoredValue);
        }
    }

    // Planned for future, not is use yet. 
    [Event(4654, Level = EventLevel.Warning, Channel = EventChannel.Operational,
        Task = Tasks.CertificateContentValidator, Keywords = EventKeywords.None)]
    public void CCVal_4654_SAN_Failed_Mandatory(int requestId, string subjectAltName)
    {
        if (IsEnabled())
        {
            WriteEvent(4654, requestId, subjectAltName);
        }
    }

    #endregion
}