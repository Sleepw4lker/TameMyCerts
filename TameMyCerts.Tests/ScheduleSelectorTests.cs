using System;
using System.Collections.Generic;
using TameMyCerts.Models;
using Xunit;

namespace TameMyCerts.Tests;

public class ScheduleSelectorTests
{
    private static TimeWindow Window(DayOfWeek day, int startHour, int endHour)
    {
        return new TimeWindow
        {
            Day = day,
            Start = new TimeSpan(startHour, 0, 0),
            End = new TimeSpan(endHour, 0, 0)
        };
    }

    [Fact]
    public void GetPreviousRandomOccurrence_ReturnsWindowFromExample()
    {
        // Arrange: Mon 8-10, Tue 12-14 (from the original example)
        var windows = new List<TimeWindow>
        {
            Window(DayOfWeek.Monday, 8, 10),
            Window(DayOfWeek.Tuesday, 12, 14)
        };

        // Thu 23.07.2026, 13:05 UTC
        var reference = new DateTimeOffset(2026, 7, 23, 13, 5, 0, TimeSpan.Zero);

        // Act
        var result = ScheduleSelector.GetPreviousRandomOccurrence(windows, reference);

        // Assert: expected result is Tue 21.07.2026, time between 12:00 and 14:00
        Assert.Equal(new DateTime(2026, 7, 21), result.Date);
        Assert.Equal(DayOfWeek.Tuesday, result.DayOfWeek);
        Assert.InRange(result.TimeOfDay, TimeSpan.FromHours(12), TimeSpan.FromHours(14));
        Assert.True(result < reference);
    }

    [Fact]
    public void GetPreviousRandomOccurrence_NeverReturnsTimeAfterReference()
    {
        var windows = new List<TimeWindow>
        {
            Window(DayOfWeek.Monday, 8, 10),
            Window(DayOfWeek.Tuesday, 12, 14),
            Window(DayOfWeek.Friday, 6, 22)
        };

        var reference = new DateTimeOffset(2026, 7, 23, 13, 5, 0, TimeSpan.Zero);

        // Run multiple times since the result is randomized within the chosen window
        for (var i = 0; i < 200; i++)
        {
            var result = ScheduleSelector.GetPreviousRandomOccurrence(windows, reference);
            Assert.True(result <= reference, $"Result {result} is after the reference {reference}");
        }
    }

    [Fact]
    public void GetPreviousRandomOccurrence_RandomTimeAlwaysWithinConfiguredWindow()
    {
        var windows = new List<TimeWindow>
        {
            Window(DayOfWeek.Tuesday, 12, 14)
        };

        var reference = new DateTimeOffset(2026, 7, 23, 13, 5, 0, TimeSpan.Zero);

        for (var i = 0; i < 200; i++)
        {
            var result = ScheduleSelector.GetPreviousRandomOccurrence(windows, reference);
            Assert.Equal(DayOfWeek.Tuesday, result.DayOfWeek);
            Assert.InRange(result.TimeOfDay, TimeSpan.FromHours(12), TimeSpan.FromHours(14));
        }
    }

    [Fact]
    public void GetPreviousRandomOccurrence_CapsResult_WhenTodaysWindowIsStillRunning()
    {
        // Window is still running "today" (10-16), reference is right in the middle at 13:00.
        var windows = new List<TimeWindow>
        {
            Window(DayOfWeek.Thursday, 10, 16)
        };

        // Thu 23.07.2026, 13:00 UTC (in the middle of the running window)
        var reference = new DateTimeOffset(2026, 7, 23, 13, 0, 0, TimeSpan.Zero);

        for (var i = 0; i < 200; i++)
        {
            var result = ScheduleSelector.GetPreviousRandomOccurrence(windows, reference);

            // Result must be on the same day, between window start (10:00) and the
            // capped end = reference time (13:00) - never after it.
            Assert.Equal(reference.Date, result.Date);
            Assert.InRange(result.TimeOfDay, TimeSpan.FromHours(10), TimeSpan.FromHours(13));
            Assert.True(result <= reference);
        }
    }

    [Fact]
    public void GetPreviousRandomOccurrence_PicksNearestOfMultipleCandidates()
    {
        // Three windows in the same week before the reference: Monday, Wednesday, Friday.
        // Reference is Saturday -> the nearest (most recent) window is Friday's.
        var windows = new List<TimeWindow>
        {
            Window(DayOfWeek.Monday, 8, 10),
            Window(DayOfWeek.Wednesday, 8, 10),
            Window(DayOfWeek.Friday, 8, 10)
        };

        // Sat 25.07.2026, 09:00 UTC
        var reference = new DateTimeOffset(2026, 7, 25, 9, 0, 0, TimeSpan.Zero);

        var result = ScheduleSelector.GetPreviousRandomOccurrence(windows, reference);

        Assert.Equal(DayOfWeek.Friday, result.DayOfWeek);
        Assert.Equal(new DateTime(2026, 7, 24), result.Date);
    }

    [Fact]
    public void GetPreviousRandomOccurrence_GoesBackAWeek_WhenWindowOnSameWeekdayNotYetStarted()
    {
        // Window falls on the same weekday as the reference, but the reference time is
        // BEFORE the window start -> the previous week's occurrence must be chosen instead
        // of today's (not yet started) window.
        var windows = new List<TimeWindow>
        {
            Window(DayOfWeek.Thursday, 14, 16)
        };

        // Thu 23.07.2026, 09:00 UTC (window doesn't start until 14:00)
        var reference = new DateTimeOffset(2026, 7, 23, 9, 0, 0, TimeSpan.Zero);

        var result = ScheduleSelector.GetPreviousRandomOccurrence(windows, reference);

        Assert.Equal(new DateTime(2026, 7, 16), result.Date); // previous Thursday
        Assert.InRange(result.TimeOfDay, TimeSpan.FromHours(14), TimeSpan.FromHours(16));
    }

    [Fact]
    public void GetPreviousRandomOccurrence_ReturnsExactStart_WhenReferenceEqualsWindowStart()
    {
        var windows = new List<TimeWindow>
        {
            Window(DayOfWeek.Tuesday, 12, 14)
        };

        // Reference exactly at window start: Tue 21.07.2026, 12:00 UTC
        var reference = new DateTimeOffset(2026, 7, 21, 12, 0, 0, TimeSpan.Zero);

        var result = ScheduleSelector.GetPreviousRandomOccurrence(windows, reference);

        Assert.Equal(reference, result);
    }

    [Fact]
    public void GetPreviousRandomOccurrence_ThrowsException_WhenNoWindowsConfigured()
    {
        var windows = new List<TimeWindow>();
        var reference = new DateTimeOffset(2026, 7, 23, 13, 5, 0, TimeSpan.Zero);

        Assert.Throws<InvalidOperationException>(() =>
            ScheduleSelector.GetPreviousRandomOccurrence(windows, reference));
    }

    [Fact]
    public void GetPreviousRandomOccurrence_ConvertsNonUtcReferenceCorrectly()
    {
        var windows = new List<TimeWindow>
        {
            Window(DayOfWeek.Tuesday, 12, 14)
        };

        // Thu 23.07.2026, 15:05 in UTC+2 is equivalent to 13:05 UTC (same as the first test)
        var reference = new DateTimeOffset(2026, 7, 23, 15, 5, 0, TimeSpan.FromHours(2));

        var result = ScheduleSelector.GetPreviousRandomOccurrence(windows, reference);

        Assert.Equal(TimeSpan.Zero, result.Offset);
        Assert.Equal(new DateTime(2026, 7, 21), result.Date);
        Assert.InRange(result.TimeOfDay, TimeSpan.FromHours(12), TimeSpan.FromHours(14));
    }

    [Fact]
    public void GetPreviousRandomOccurrence_MultipleWindowsSameDay_PicksLatestApplicable()
    {
        // Two windows on the same weekday; the later one should win if both are in the past.
        var windows = new List<TimeWindow>
        {
            Window(DayOfWeek.Tuesday, 6, 8),
            Window(DayOfWeek.Tuesday, 12, 14)
        };

        var reference = new DateTimeOffset(2026, 7, 23, 13, 5, 0, TimeSpan.Zero);

        var result = ScheduleSelector.GetPreviousRandomOccurrence(windows, reference);

        Assert.InRange(result.TimeOfDay, TimeSpan.FromHours(12), TimeSpan.FromHours(14));
    }
}