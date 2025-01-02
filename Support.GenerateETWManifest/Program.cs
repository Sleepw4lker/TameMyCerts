using System.Diagnostics.Tracing;
using TameMyCerts;
using System.IO;
using System;

// Generate the manifest
internal class Program
{
    private static void Main(string[] args)
    {
        string? manifest = EventSource.GenerateManifest(typeof(ETWLogger), "TameMyCerts.Events.dll");
        // Save the manifest to a file
        if (manifest is not null)
        {
            File.WriteAllText("TameMyCerts.Events.man", manifest);
            Console.WriteLine("Manifest generated and saved to TameMyCerts.Events.man");
        }
        else
        {
            Console.WriteLine("Failed to generate manifest. The manifest content is null.");
        }
    }
}