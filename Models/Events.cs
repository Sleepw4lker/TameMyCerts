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

using System.Diagnostics;
using TameMyCerts.Enums;

namespace TameMyCerts.Models
{
    internal static class Events
    {
        public static readonly Event PDEF_SUCCESS_INIT = new Event
        {
            Id = 1,
            LogLevel = CertSrv.CERTLOG_VERBOSE,
            MessageText = LocalizedStrings.Events_PDEF_SUCCESS_INIT
        };

        public static readonly Event PDEF_FAIL_INIT = new Event
        {
            Id = 2,
            LogLevel = CertSrv.CERTLOG_ERROR,
            Type = EventLogEntryType.Error,
            MessageText = LocalizedStrings.Events_PDEF_FAIL_INIT
        };

        public static readonly Event PDEF_FAIL_SHUTDOWN = new Event
        {
            Id = 4,
            LogLevel = CertSrv.CERTLOG_ERROR,
            Type = EventLogEntryType.Error,
            MessageText = LocalizedStrings.Events_PDEF_FAIL_SHUTDOWN
        };

        public static readonly Event REQUEST_DENIED_AUDIT = new Event
        {
            Id = 5,
            LogLevel = CertSrv.CERTLOG_MINIMAL,
            Type = EventLogEntryType.Warning,
            MessageText = LocalizedStrings.Events_REQUEST_DENIED_AUDIT
        };

        public static readonly Event REQUEST_DENIED = new Event
        {
            Id = 6,
            Type = EventLogEntryType.Warning,
            MessageText = LocalizedStrings.Events_REQUEST_DENIED
        };

        public static readonly Event POLICY_NOT_FOUND = new Event
        {
            Id = 7,
            LogLevel = CertSrv.CERTLOG_VERBOSE,
            Type = EventLogEntryType.Warning,
            MessageText = LocalizedStrings.Events_POLICY_NOT_FOUND
        };

        public static readonly Event MODULE_NOT_SUPPORTED = new Event
        {
            Id = 9,
            LogLevel = CertSrv.CERTLOG_ERROR,
            Type = EventLogEntryType.Error,
            MessageText = LocalizedStrings.Events_MODULE_NOT_SUPPORTED
        };

        public static readonly Event REQUEST_DENIED_NO_TEMPLATE_INFO = new Event
        {
            Id = 10,
            LogLevel = CertSrv.CERTLOG_ERROR,
            Type = EventLogEntryType.Error,
            MessageText = LocalizedStrings.Events_REQUEST_DENIED_NO_TEMPLATE_INFO
        };

        public static readonly Event REQUEST_DENIED_NO_TEMPLATE_INFO_LOCAL = new Event
        {
            Id = 10,
            LogLevel = CertSrv.CERTLOG_ERROR,
            Type = EventLogEntryType.Error,
            MessageText = LocalizedStrings.Events_REQUEST_DENIED_NO_TEMPLATE_INFO_LOCAL
        };

        public static readonly Event REQUEST_DENIED_NO_POLICY = new Event
        {
            Id = 10,
            LogLevel = CertSrv.CERTLOG_ERROR,
            Type = EventLogEntryType.Error,
            MessageText = LocalizedStrings.Events_REQUEST_DENIED_NO_POLICY
        };

        public static readonly Event PDEF_REQUEST_DENIED = new Event
        {
            Id = 11,
            LogLevel = CertSrv.CERTLOG_VERBOSE,
            MessageText = LocalizedStrings.Events_PDEF_REQUEST_DENIED
        };

        public static readonly Event PDEF_REQUEST_DENIED_MESSAGE = new Event
        {
            Id = 11,
            LogLevel = CertSrv.CERTLOG_VERBOSE,
            MessageText = LocalizedStrings.Events_PDEF_REQUEST_DENIED_MESSAGE
        };

        public static readonly Event DEBUG = new Event
        {
            Id = 99,
            LogLevel = CertSrv.CERTLOG_VERBOSE,
            MessageText = "Debug: {0}"
        };
    }
}