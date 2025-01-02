using System.Diagnostics.Tracing;
using TameMyCerts;

    // Generate the manifest
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