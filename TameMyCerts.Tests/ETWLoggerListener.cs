using System.Collections.Generic;
using System.Diagnostics.Tracing;

namespace TameMyCerts.Tests;

public class ETWLoggerListener : EventListener
{
    public List<EventWrittenEventArgs> Events { get; } = new();

    protected override void OnEventWritten(EventWrittenEventArgs eventData)
    {
        Events.Add(eventData);
    }

    public void ClearEvents()
    {
        Events.Clear();
    }

    protected override void OnEventSourceCreated(EventSource eventSource)
    {
        if (eventSource.Name == "TameMyCerts-TameMyCerts-Policy")
        {
            EnableEvents(eventSource, EventLevel.LogAlways, (EventKeywords)(-1));
        }
    }
}