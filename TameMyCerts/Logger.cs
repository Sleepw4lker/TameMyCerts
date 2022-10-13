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

using System.Diagnostics;
using System.Security;
using TameMyCerts.Models;

namespace TameMyCerts
{
    internal class Logger
    {
        private readonly EventLog _eventLog;
        private readonly int _logLevel;

        public Logger(string eventSource, int logLevel = CertSrv.CERTLOG_WARNING)
        {
            const string logName = "Application";

            _logLevel = logLevel;
            
            _eventLog = new EventLog(logName)
            {
                Source = CreateEventSource(eventSource, logName)
            };
        }

        public void Log(Event logEvent, params object[] args)
        {
            if (_logLevel >= logEvent.LogLevel)
            {
                _eventLog.WriteEntry(
                    string.Format(logEvent.MessageText, args),
                    logEvent.Type,
                    logEvent.Id);
            }
        }

        private static string CreateEventSource(string currentAppName, string logName)
        {
            var eventSource = currentAppName;

            try
            {
                if (!EventLog.SourceExists(eventSource))
                {
                    EventLog.CreateEventSource(eventSource, logName);
                }
            }
            catch (SecurityException)
            {
                eventSource = "Application";
            }

            return eventSource;
        }
    }

    public static class Events
    {
        public static Event PDEF_SUCCESS_INIT = new Event
        {
            Id = 1,
            LogLevel = CertSrv.CERTLOG_VERBOSE,
            MessageText = LocalizedStrings.Events_PDEF_SUCCESS_INIT
        };

        public static Event PDEF_FAIL_INIT = new Event
        {
            Id = 2,
            LogLevel = CertSrv.CERTLOG_ERROR,
            Type = EventLogEntryType.Error,
            MessageText = LocalizedStrings.Events_PDEF_FAIL_INIT
        };

        public static Event PDEF_FAIL_VERIFY = new Event
        {
            Id = 3,
            LogLevel = CertSrv.CERTLOG_ERROR,
            Type = EventLogEntryType.Error,
            MessageText = LocalizedStrings.Events_PDEF_FAIL_VERIFY
        };

        public static Event PDEF_FAIL_SHUTDOWN = new Event
        {
            Id = 4,
            LogLevel = CertSrv.CERTLOG_ERROR,
            Type = EventLogEntryType.Error,
            MessageText = LocalizedStrings.Events_PDEF_FAIL_SHUTDOWN
        };

        public static Event REQUEST_DENIED_AUDIT = new Event
        {
            Id = 5,
            LogLevel = CertSrv.CERTLOG_MINIMAL,
            Type = EventLogEntryType.Warning,
            MessageText = LocalizedStrings.Events_REQUEST_DENIED_AUDIT
        };

        public static Event REQUEST_DENIED = new Event
        {
            Id = 6,
            Type = EventLogEntryType.Warning,
            MessageText = LocalizedStrings.Events_REQUEST_DENIED
        };

        public static Event POLICY_NOT_FOUND = new Event
        {
            Id = 7,
            LogLevel = CertSrv.CERTLOG_VERBOSE,
            Type = EventLogEntryType.Warning,
            MessageText = LocalizedStrings.Events_POLICY_NOT_FOUND
        };

        public static Event MODULE_NOT_SUPPORTED = new Event
        {
            Id = 9,
            LogLevel = CertSrv.CERTLOG_ERROR,
            Type = EventLogEntryType.Error,
            MessageText = LocalizedStrings.Events_MODULE_NOT_SUPPORTED
        };

        public static Event REQUEST_DENIED_NO_TEMPLATE_INFO = new Event
        {
            Id = 10,
            LogLevel = CertSrv.CERTLOG_ERROR,
            Type = EventLogEntryType.Error,
            MessageText = LocalizedStrings.Events_REQUEST_DENIED_NO_TEMPLATE_INFO
        };

        public static Event REQUEST_DENIED_NO_TEMPLATE_INFO_LOCAL = new Event
        {
            Id = 10,
            LogLevel = CertSrv.CERTLOG_ERROR,
            Type = EventLogEntryType.Error,
            MessageText = LocalizedStrings.Events_REQUEST_DENIED_NO_TEMPLATE_INFO_LOCAL
        };

        public static Event REQUEST_DENIED_NO_POLICY = new Event
        {
            Id = 10,
            LogLevel = CertSrv.CERTLOG_ERROR,
            Type = EventLogEntryType.Error,
            MessageText = LocalizedStrings.Events_REQUEST_DENIED_NO_POLICY
        };

        public static Event PDEF_REQUEST_DENIED = new Event
        {
            Id = 11,
            LogLevel = CertSrv.CERTLOG_VERBOSE,
            MessageText = LocalizedStrings.Events_PDEF_REQUEST_DENIED
        };

        public static Event PDEF_REQUEST_DENIED_MESSAGE = new Event
        {
            Id = 11,
            LogLevel = CertSrv.CERTLOG_VERBOSE,
            MessageText = LocalizedStrings.Events_PDEF_REQUEST_DENIED_MESSAGE
        };

        public static Event REQUEST_DENIED_INSECURE_FLAGS = new Event
        {
            Id = 12,
            LogLevel = CertSrv.CERTLOG_ERROR,
            Type = EventLogEntryType.Error,
            MessageText = LocalizedStrings.Events_REQUEST_DENIED_INSECURE_FLAGS
        };

        public static Event VALIDITY_REDUCED = new Event
        {
            Id = 13,
            LogLevel = CertSrv.CERTLOG_VERBOSE,
            Type = EventLogEntryType.Information,
            MessageText = LocalizedStrings.Events_VALIDITY_REDUCED
        };

        public static Event STARTDATE_SET = new Event
        {
            Id = 14,
            LogLevel = CertSrv.CERTLOG_VERBOSE,
            Type = EventLogEntryType.Information,
            MessageText = LocalizedStrings.Events_STARTDATE_SET
        };

        public static Event STARTDATE_INVALID = new Event
        {
            Id = 15,
            LogLevel = CertSrv.CERTLOG_WARNING,
            Type = EventLogEntryType.Warning,
            MessageText = LocalizedStrings.Events_STARTDATE_INVALID
        };

        public static Event ATTRIB_ERR_PARSE = new Event
        {
            Id = 16,
            LogLevel = CertSrv.CERTLOG_WARNING,
            Type = EventLogEntryType.Warning,
            MessageText = LocalizedStrings.Events_ATTRIB_ERR_PARSE
        };
    }

    public class Event
    {
        public int Id { get; set; }
        public int LogLevel { get; set; } = CertSrv.CERTLOG_WARNING;
        public EventLogEntryType Type { get; set; } = EventLogEntryType.Information;
        public string MessageText { get; set; }
    }
}