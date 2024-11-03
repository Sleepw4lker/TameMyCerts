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

namespace TameMyCerts.Models;

internal class Event
{
    public int Id { get; set; }
    public int LogLevel { get; set; } = CertSrv.CERTLOG_WARNING;
    public EventLogEntryType Type { get; set; } = EventLogEntryType.Information;
    public string MessageText { get; set; }
}