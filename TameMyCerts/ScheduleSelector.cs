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
using TameMyCerts.Models;

namespace TameMyCerts;

public class ScheduleSelector
{
    private static readonly Random _rng = new();

    public static DateTimeOffset GetPreviousRandomOccurrence(
        IEnumerable<TimeWindow> windows,
        DateTimeOffset reference)
    {
        var refUtc = reference.ToUniversalTime();

        DateTimeOffset? bestStart = null;
        DateTimeOffset bestEnd = default;

        foreach (var window in windows)
        {
            for (var diff = 0; diff <= 7; diff++)
            {
                var candidateDate = refUtc.Date.AddDays(-diff);
                if (candidateDate.DayOfWeek != window.Day)
                {
                    continue;
                }

                var start = new DateTimeOffset(candidateDate, TimeSpan.Zero) + window.Start;
                var end = new DateTimeOffset(candidateDate, TimeSpan.Zero) + window.End;

                if (start > refUtc)
                {
                    continue;
                }

                if (end > refUtc)
                {
                    end = refUtc;
                }

                if (bestStart == null || start > bestStart.Value)
                {
                    bestStart = start;
                    bestEnd = end;
                }

                break;
            }
        }

        if (bestStart == null)
        {
            throw new InvalidOperationException(
                "Kein passendes Zeitfenster in der Vergangenheit gefunden.");
        }

        return RandomTimeWithin(bestStart.Value, bestEnd);
    }

    private static DateTimeOffset RandomTimeWithin(DateTimeOffset start, DateTimeOffset end)
    {
        if (end <= start)
        {
            return start;
        }

        var startTicks = start.UtcTicks;
        var endTicks = end.UtcTicks;
        var randomTicks = startTicks + (long)(_rng.NextDouble() * (endTicks - startTicks));

        return new DateTimeOffset(randomTicks, TimeSpan.Zero);
    }
}