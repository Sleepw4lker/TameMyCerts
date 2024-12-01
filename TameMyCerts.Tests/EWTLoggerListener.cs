using System.Collections.Generic;
using System.Diagnostics.Tracing;
using TameMyCerts;

namespace TameMyCerts.Tests
{
    public class EWTLoggerListener : EventListener
    {
        private readonly List<EventWrittenEventArgs> events = new List<EventWrittenEventArgs>();
        protected override void OnEventWritten(EventWrittenEventArgs eventData) { events.Add(eventData); }
        public List<EventWrittenEventArgs> Events => events;
        public void ClearEvents() { events.Clear(); }

        protected override void OnEventSourceCreated(EventSource eventSource)
        {
            if (eventSource.Name == "TameMyCerts-TameMyCerts-Policy")
            {
                EnableEvents(eventSource, EventLevel.LogAlways, (EventKeywords)(-1));
            }
        }
    }
}
