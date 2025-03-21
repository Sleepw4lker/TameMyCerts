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

using System.Diagnostics;
using TameMyCerts.Enums;

namespace TameMyCerts.Models;

internal static class Events
{
    public static readonly Event PDEF_SUCCESS_INIT = new()
    {
        Id = 1,
        LogLevel = CertSrv.CERTLOG_VERBOSE,
        MessageText = LocalizedStrings.Events_PDEF_SUCCESS_INIT
    };

    public static readonly Event PDEF_FAIL_INIT = new()
    {
        Id = 2,
        LogLevel = CertSrv.CERTLOG_ERROR,
        Type = EventLogEntryType.Error,
        MessageText = LocalizedStrings.Events_PDEF_FAIL_INIT
    };

    public static readonly Event PDEF_FAIL_SHUTDOWN = new()
    {
        Id = 4,
        LogLevel = CertSrv.CERTLOG_ERROR,
        Type = EventLogEntryType.Error,
        MessageText = LocalizedStrings.Events_PDEF_FAIL_SHUTDOWN
    };

    public static readonly Event REQUEST_DENIED_AUDIT = new()
    {
        Id = 5,
        LogLevel = CertSrv.CERTLOG_MINIMAL,
        Type = EventLogEntryType.Warning,
        MessageText = LocalizedStrings.Events_REQUEST_DENIED_AUDIT
    };

    public static readonly Event REQUEST_DENIED = new()
    {
        Id = 6,
        Type = EventLogEntryType.Warning,
        MessageText = LocalizedStrings.Events_REQUEST_DENIED
    };

    public static readonly Event POLICY_NOT_FOUND = new()
    {
        Id = 7,
        LogLevel = CertSrv.CERTLOG_VERBOSE,
        Type = EventLogEntryType.Warning,
        MessageText = LocalizedStrings.Events_POLICY_NOT_FOUND
    };

    public static readonly Event REQUEST_DENIED_POLICY_NOT_FOUND = new()
    {
        Id = 8,
        LogLevel = CertSrv.CERTLOG_VERBOSE,
        Type = EventLogEntryType.Warning,
        MessageText = LocalizedStrings.Events_REQUEST_DENIED_POLICY_NOT_FOUND
    };

    public static readonly Event MODULE_NOT_SUPPORTED = new()
    {
        Id = 9,
        LogLevel = CertSrv.CERTLOG_ERROR,
        Type = EventLogEntryType.Error,
        MessageText = LocalizedStrings.Events_MODULE_NOT_SUPPORTED
    };

    public static readonly Event REQUEST_DENIED_NO_TEMPLATE_INFO_LOCAL = new()
    {
        Id = 10,
        LogLevel = CertSrv.CERTLOG_ERROR,
        Type = EventLogEntryType.Error,
        MessageText = LocalizedStrings.Events_REQUEST_DENIED_NO_TEMPLATE_INFO_LOCAL
    };

    public static readonly Event REQUEST_DENIED_NO_POLICY = new()
    {
        Id = 10,
        LogLevel = CertSrv.CERTLOG_ERROR,
        Type = EventLogEntryType.Error,
        MessageText = LocalizedStrings.Events_REQUEST_DENIED_NO_POLICY
    };

    public static readonly Event PDEF_REQUEST_DENIED = new()
    {
        Id = 11,
        LogLevel = CertSrv.CERTLOG_VERBOSE,
        MessageText = LocalizedStrings.Events_PDEF_REQUEST_DENIED
    };

    public static readonly Event PDEF_REQUEST_DENIED_MESSAGE = new()
    {
        Id = 11,
        LogLevel = CertSrv.CERTLOG_VERBOSE,
        MessageText = LocalizedStrings.Events_PDEF_REQUEST_DENIED_MESSAGE
    };

    public static readonly Event SUCCESS_ISSUED = new()
    {
        Id = 12,
        LogLevel = CertSrv.CERTLOG_VERBOSE,
        MessageText = LocalizedStrings.Events_SUCCESS_ISSUED
    };

    public static readonly Event SUCCESS_PENDING = new()
    {
        Id = 13,
        LogLevel = CertSrv.CERTLOG_VERBOSE,
        MessageText = LocalizedStrings.Events_SUCCESS_PENDING
    };

    public static readonly Event REQUEST_CONTAINS_WARNINGS = new()
    {
        Id = 14,
        Type = EventLogEntryType.Warning,
        MessageText = LocalizedStrings.Events_REQUEST_CONTAINS_WARNINGS
    };

    public static readonly Event DEBUG = new()
    {
        Id = 99,
        LogLevel = CertSrv.CERTLOG_VERBOSE,
        MessageText = "Debug: {0}"
    };
}