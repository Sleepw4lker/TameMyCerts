using System;
using System.Collections.Generic;
using System.Diagnostics.Tracing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TameMyCerts.Enums;
using TameMyCerts.Models;
using TameMyCerts.Validators;

namespace TameMyCerts
{
    [EventSource(Name = "TameMyCerts-TameMyCerts-Policy", LocalizationResources = "TameMyCerts.LocalizedStrings")]
    // This needs to be named Company-Product-Component, it is hardcoded into EventViewer.
    public sealed class ETWLogger : EventSource
    {
        public static ETWLogger Log = new ETWLogger();
       
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
        [Event(1, Level = EventLevel.Informational, Channel = EventChannel.Admin, Task = Tasks.TameMyCerts, Keywords = EventKeywords.None)]
        public void TMC_1_PolicyModule_Success_Initiated(string policyModule, string version)
        {
            if (IsEnabled())
            {
                WriteEvent(1, policyModule, version);
            }
        }
        [Event(2, Level = EventLevel.Error, Channel = EventChannel.Admin, Task = Tasks.TameMyCerts, Keywords = EventKeywords.None)]
        public void TMC_2_PolicyModule_Failed_Initiated(string exception)
        {
            if (IsEnabled())
            {
                WriteEvent(2, exception);
            }
        }
        [Event(4, Level = EventLevel.Error, Channel = EventChannel.Admin, Task = Tasks.TameMyCerts, Keywords = EventKeywords.None)]
        public void TMC_4_PolicyModule_Default_Shutdown_Failed(string exception)
        {
            if (IsEnabled())
            {
                WriteEvent(4, exception);
            }
        }
        [Event(5, Level = EventLevel.Informational, Channel = EventChannel.Analytic, Task = Tasks.TameMyCerts, Keywords = EventKeywords.None)]
        public void TMC_5_Analytical_Audit_only_Deny(int requestID, string template, string reason)
        {
            if (IsEnabled())
            {
                WriteEvent(5, requestID, template, reason);
            }
        }
        [Event(6, Level = EventLevel.Informational, Channel = EventChannel.Admin, Task = Tasks.TameMyCerts, Keywords = EventKeywords.None)]
        public void TMC_6_Deny_Issuing_Request(int requestID, string template, string reason)
        {
            if (IsEnabled())
            {
                WriteEvent(6, requestID, template, reason);
            }
        }
        [Event(12, Level = EventLevel.Informational, Channel = EventChannel.Admin, Task = Tasks.TameMyCerts, Keywords = EventKeywords.None)]
        public void TMC_12_Success_Issued(int requestID, string template)
        {
            if (IsEnabled())
            {
                WriteEvent(12, requestID, template);
            }
        }
        [Event(13, Level = EventLevel.Informational, Channel = EventChannel.Admin, Task = Tasks.TameMyCerts, Keywords = EventKeywords.None)]
        public void TMC_13_Success_Pending(int requestID, string template)
        {
            if (IsEnabled())
            {
                WriteEvent(13, requestID, template);
            }
        }
        [Event(91, Level = EventLevel.Informational, Channel = EventChannel.Debug, Task = Tasks.XMLParser, Keywords = EventKeywords.None)]
        public void TMC_91_Policy_Read(string templateName, string policy)
        {
            if (IsEnabled())
            {
                WriteEvent(91, templateName, policy);
            }
        }
        [Event(92, Level = EventLevel.Critical, Channel = EventChannel.Admin, Task = Tasks.XMLParser, Keywords = EventKeywords.None)]
        public void TMC_92_Policy_Unknown_XML_Element(string elementName, int lineNumber, int linePosition)
        {
            if (IsEnabled())
            {
                WriteEvent(92, elementName, lineNumber, linePosition);
            }
        }
        [Event(93, Level = EventLevel.Critical, Channel = EventChannel.Admin, Task = Tasks.XMLParser, Keywords = EventKeywords.None)]
        public void TMC_93_Policy_Unknown_XML_Attribute(string attributeName, string attributeValue, int lineNumber, int linePosition)
        {
            if (IsEnabled())
            {
                WriteEvent(93, attributeName, attributeValue, lineNumber, linePosition);
            }
        }

        #endregion

        #region Yubico Validator events 4201-4399
        [Event(4201, Level = EventLevel.Warning, Channel = EventChannel.Operational, Task = Tasks.YubikeyValidator, Keywords = EventKeywords.None)]
        public void YKVal_4201_Denied_by_Policy(string denyingPolicy, int requestID)
        {
            if (IsEnabled())
            {
                WriteEvent(4201, denyingPolicy, requestID);
            }
        }
        [Event(4202, Level = EventLevel.Warning, Channel = EventChannel.Operational, Task = Tasks.YubikeyValidator, Keywords = EventKeywords.None)]
        public void YKVal_4202_Denied_by_Policy(int requestID)
        {
            if (IsEnabled())
            {
                WriteEvent(4202, requestID);
            }
        }
        [Event(4203, Level = EventLevel.Warning, Channel = EventChannel.Operational, Task = Tasks.YubikeyValidator, Keywords = EventKeywords.None)]
        public void YKVal_4203_Denied_due_to_no_matching_policy_default_deny(int requestID)
        {
            if (IsEnabled())
            {
                WriteEvent(4203, requestID);
            }
        }
        [Event(4204, Level = EventLevel.Verbose, Channel = EventChannel.Operational, Task = Tasks.YubikeyValidator, Keywords = EventKeywords.None)]
        public void YKVal_4204_Matching_policy(string policy, int requestID)
        {
            if (IsEnabled())
            {
                WriteEvent(4204, policy, requestID);
            }
        }
        [Event(4205, Level = EventLevel.Error, Channel = EventChannel.Operational, Task = Tasks.YubikeyValidator, Keywords = EventKeywords.None)]
        public void YKVal_4205_Failed_to_extract_Yubikey_Attestion(int requestID)
        {
            if (IsEnabled())
            {
                WriteEvent(4205, requestID);
            }
        }
        [Event(4206, Level = EventLevel.Warning, Channel = EventChannel.Debug, Task = Tasks.YubikeyValidator, Keywords = EventKeywords.None)]
        public void YKVal_4206_Debug_failed_to_match_policy(int requestID, string policy)
        {
            if (IsEnabled())
            {
                WriteEvent(4206, requestID, policy);
            }
        }
        [Event(4207, Level = EventLevel.Error, Channel = EventChannel.Operational, Task = Tasks.YubikeyValidator, Keywords = EventKeywords.None)]
        public void YKVal_4207_Yubikey_Attestion_Missmatch_with_CSR(int requestID)
        {
            if (IsEnabled())
            {
                WriteEvent(4207, requestID);
            }
        }
        [Event(4208, Level = EventLevel.Error, Channel = EventChannel.Operational, Task = Tasks.YubikeyValidator, Keywords = EventKeywords.None)]
        public void YKVal_4208_Yubikey_Attestion_Failed_to_build(int requestID)
        {
            if (IsEnabled())
            {
                WriteEvent(4208, requestID);
            }
        }
        [Event(4209, Level = EventLevel.Informational, Channel = EventChannel.Debug, Task = Tasks.YubikeyValidator, Keywords = EventKeywords.None)]
        public void YKVal_4209_Found_Attestation_Location(int requestID, string attestationLocation)
        {
            if (IsEnabled())
            {
                WriteEvent(4209, requestID, attestationLocation);
            }
        }
        #endregion

        #region FileSystemStorer events 4401-4499
        #endregion

        #region Certificate Content Validator events 4601-4799
        [Event(4601, Level = EventLevel.Informational, Channel = EventChannel.Operational, Task = Tasks.CertificateContentValidator, Keywords = EventKeywords.None)]
        public void CCVal_4601_(string denyingPolicy, int requestID)
        {
            if (IsEnabled())
            {
                WriteEvent(4601, denyingPolicy, requestID);
            }
        }
        [Event(4651, Level = EventLevel.Verbose, Channel = EventChannel.Debug, Task = Tasks.CertificateContentValidator, Keywords = EventKeywords.None)]
        public void CCVal_4651_SAN_Already_Exists(int requestID, string subjectAltName, string currentValue, string ignoredValue)
        {
            if (IsEnabled())
            {
                WriteEvent(4651, requestID, subjectAltName, currentValue, ignoredValue);
            }
        }
        [Event(4652, Level = EventLevel.Verbose, Channel = EventChannel.Debug, Task = Tasks.CertificateContentValidator, Keywords = EventKeywords.None)]
        public void CCVal_4652_SAN_Added(int requestID, string subjectAltName, string addedValue)
        {
            if (IsEnabled())
            {
                WriteEvent(4652, requestID, subjectAltName, addedValue);
            }
        }
        [Event(4653, Level = EventLevel.Verbose, Channel = EventChannel.Debug, Task = Tasks.CertificateContentValidator, Keywords = EventKeywords.None)]
        public void CCVal_4653_SAN_Failed_to_add(int requestID, string subjectAltName, string ignoredValue)
        {
            if (IsEnabled())
            {
                WriteEvent(4653, requestID, subjectAltName, ignoredValue);
            }
        }
        // Planned for future, not is use yet. 
        [Event(4654, Level = EventLevel.Warning, Channel = EventChannel.Operational, Task = Tasks.CertificateContentValidator, Keywords = EventKeywords.None)]
        public void CCVal_4654_SAN_Failed_Mandatory(int requestID, string subjectAltName)
        {
            if (IsEnabled())
            {
                WriteEvent(4654, requestID, subjectAltName);
            }
        }
        #endregion
    }
}
