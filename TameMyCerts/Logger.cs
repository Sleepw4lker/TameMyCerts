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
using System.Security;
using TameMyCerts.Enums;
using TameMyCerts.Models;

namespace TameMyCerts;

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
            _eventLog.WriteEntry(string.Format(logEvent.MessageText, args), logEvent.Type, logEvent.Id);
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