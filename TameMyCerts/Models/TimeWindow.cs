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
using System.Xml.Serialization;

namespace TameMyCerts.Models;

public class TimeWindow
{
    [XmlElement(ElementName = "Day")]
    public DayOfWeek Day { get; set; }

    [XmlElement(ElementName = "Start")]
    public string StartRaw { get; set; } = "00:00:00";

    [XmlElement(ElementName = "End")]
    public string EndRaw { get; set; } = "00:00:00";

    [XmlIgnore]
    public TimeSpan Start
    {
        get => TimeSpan.Parse(StartRaw);
        set => StartRaw = value.ToString(@"hh\:mm\:ss");
    }

    [XmlIgnore]
    public TimeSpan End
    {
        get => TimeSpan.Parse(EndRaw);
        set => EndRaw = value.ToString(@"hh\:mm\:ss");
    }

    public override string ToString() => $"{Day} {StartRaw}-{EndRaw} UTC";
}