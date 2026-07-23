using System;
using System.IO;
using System.Text;
using System.Xml.Serialization;
using TameMyCerts.Models;
using Xunit;

namespace TameMyCerts.Tests;

public class TimeWindowTests
{
    [Fact]
    public void DefaultValues_AreZeroTimeSpan()
    {
        var window = new TimeWindow();

        Assert.Equal("00:00:00", window.StartRaw);
        Assert.Equal("00:00:00", window.EndRaw);
        Assert.Equal(TimeSpan.Zero, window.Start);
        Assert.Equal(TimeSpan.Zero, window.End);
    }

    [Theory]
    [InlineData(8, 0, 0, "08:00:00")]
    [InlineData(0, 0, 0, "00:00:00")]
    [InlineData(23, 59, 59, "23:59:59")]
    [InlineData(9, 5, 3, "09:05:03")]
    public void Start_Set_FormatsRawStringWithLeadingZeros(int h, int m, int s, string expectedRaw)
    {
        var window = new TimeWindow { Start = new TimeSpan(h, m, s) };

        Assert.Equal(expectedRaw, window.StartRaw);
    }

    [Theory]
    [InlineData(10, 0, 0, "10:00:00")]
    [InlineData(14, 30, 0, "14:30:00")]
    public void End_Set_FormatsRawStringWithLeadingZeros(int h, int m, int s, string expectedRaw)
    {
        var window = new TimeWindow { End = new TimeSpan(h, m, s) };

        Assert.Equal(expectedRaw, window.EndRaw);
    }

    [Fact]
    public void Start_Get_ParsesRawStringCorrectly()
    {
        var window = new TimeWindow { StartRaw = "08:30:15" };

        Assert.Equal(new TimeSpan(8, 30, 15), window.Start);
    }

    [Fact]
    public void End_Get_ParsesRawStringCorrectly()
    {
        var window = new TimeWindow { EndRaw = "14:00:00" };

        Assert.Equal(new TimeSpan(14, 0, 0), window.End);
    }

    [Fact]
    public void Start_Get_ThrowsFormatException_WhenRawStringIsInvalid()
    {
        var window = new TimeWindow { StartRaw = "not-a-time" };

        Assert.Throws<FormatException>(() => window.Start);
    }

    [Fact]
    public void Day_CanBeSetAndRead()
    {
        var window = new TimeWindow { Day = DayOfWeek.Wednesday };

        Assert.Equal(DayOfWeek.Wednesday, window.Day);
    }

    [Fact]
    public void ToString_ReturnsExpectedFormat()
    {
        var window = new TimeWindow
        {
            Day = DayOfWeek.Tuesday,
            Start = new TimeSpan(12, 0, 0),
            End = new TimeSpan(14, 0, 0)
        };

        Assert.Equal("Tuesday 12:00:00-14:00:00 UTC", window.ToString());
    }

    [Fact]
    public void Xml_Serialize_RoundTrip_PreservesAllValues()
    {
        var original = new TimeWindow
        {
            Day = DayOfWeek.Friday,
            Start = new TimeSpan(6, 0, 0),
            End = new TimeSpan(22, 0, 0)
        };

        var serializer = new XmlSerializer(typeof(TimeWindow));

        using var stream = new MemoryStream();
        serializer.Serialize(stream, original);
        stream.Position = 0;

        var deserialized = (TimeWindow)serializer.Deserialize(stream)!;

        Assert.Equal(original.Day, deserialized.Day);
        Assert.Equal(original.Start, deserialized.Start);
        Assert.Equal(original.End, deserialized.End);
        Assert.Equal(original.StartRaw, deserialized.StartRaw);
        Assert.Equal(original.EndRaw, deserialized.EndRaw);
    }

    [Fact]
    public void Xml_Serialize_WritesDayStartEndAsChildElements()
    {
        var window = new TimeWindow
        {
            Day = DayOfWeek.Monday,
            Start = new TimeSpan(8, 0, 0),
            End = new TimeSpan(10, 0, 0)
        };

        var serializer = new XmlSerializer(typeof(TimeWindow));

        using var stream = new MemoryStream();
        serializer.Serialize(stream, window);
        var xml = Encoding.UTF8.GetString(stream.ToArray());

        // Day, Start and End are now expected as child elements, not attributes.
        Assert.Contains("<Day>Monday</Day>", xml);
        Assert.Contains("<Start>08:00:00</Start>", xml);
        Assert.Contains("<End>10:00:00</End>", xml);
    }

    [Fact]
    public void Xml_Serialize_DoesNotWriteDayStartEndAsAttributes()
    {
        var window = new TimeWindow
        {
            Day = DayOfWeek.Monday,
            Start = new TimeSpan(8, 0, 0),
            End = new TimeSpan(10, 0, 0)
        };

        var serializer = new XmlSerializer(typeof(TimeWindow));

        using var stream = new MemoryStream();
        serializer.Serialize(stream, window);
        var xml = Encoding.UTF8.GetString(stream.ToArray());

        // Guard against accidentally reverting to attribute-based mapping.
        Assert.DoesNotContain("Day=\"Monday\"", xml);
        Assert.DoesNotContain("Start=\"08:00:00\"", xml);
        Assert.DoesNotContain("End=\"10:00:00\"", xml);
    }

    [Fact]
    public void Xml_Deserialize_FromRawXmlString_PopulatesProperties()
    {
        const string xml =
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>" +
            "<TimeWindow>" +
            "<Day>Thursday</Day>" +
            "<Start>07:15:00</Start>" +
            "<End>09:45:00</End>" +
            "</TimeWindow>";

        var serializer = new XmlSerializer(typeof(TimeWindow));
        using var reader = new StringReader(xml);

        var window = (TimeWindow)serializer.Deserialize(reader)!;

        Assert.Equal(DayOfWeek.Thursday, window.Day);
        Assert.Equal(new TimeSpan(7, 15, 0), window.Start);
        Assert.Equal(new TimeSpan(9, 45, 0), window.End);
    }

    [Fact]
    public void XmlIgnore_Properties_AreNotDuplicatedInOutput()
    {
        var window = new TimeWindow
        {
            Day = DayOfWeek.Sunday,
            Start = new TimeSpan(1, 0, 0),
            End = new TimeSpan(2, 0, 0)
        };

        var serializer = new XmlSerializer(typeof(TimeWindow));

        using var stream = new MemoryStream();
        serializer.Serialize(stream, window);
        var xml = Encoding.UTF8.GetString(stream.ToArray());

        // The TimeSpan-typed Start/End properties are marked [XmlIgnore];
        // only the string-backed StartRaw/EndRaw values should appear as <Start>/<End>.
        // If the [XmlIgnore] attribute were accidentally removed, the TimeSpan properties
        // would produce a second element with the same name, which is not valid and
        // would either throw during serialization or duplicate the element.
        var startElementCount = CountOccurrences(xml, "<Start>");
        var endElementCount = CountOccurrences(xml, "<End>");

        Assert.Equal(1, startElementCount);
        Assert.Equal(1, endElementCount);
    }

    private static int CountOccurrences(string text, string substring)
    {
        var count = 0;
        var index = 0;
        while ((index = text.IndexOf(substring, index, StringComparison.Ordinal)) != -1)
        {
            count++;
            index += substring.Length;
        }

        return count;
    }
}