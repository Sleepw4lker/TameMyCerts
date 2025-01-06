using System.Diagnostics.Tracing;
using TameMyCerts;
using System.IO;
using System;

// Generate the manifest
internal class Program
{
    private static void Main(string[] args)
    {
        string? outFilename = null;
        for (int i = 0; i < args.Length; i++)
        {
            if (args[i] == "--outfile" && i + 1 < args.Length)
            {
                outFilename = args[i + 1]; break;
            }
        }
        // Validate the filename
        if (string.IsNullOrEmpty(outFilename))
        {
            throw new ArgumentException("Missing or invalid --outfile argument");
        }

        // Generate the manifest
        string? manifest = EventSource.GenerateManifest(typeof(ETWLogger), "TameMyCerts.Events.dll");
        // Save the manifest to a file
        if (manifest is not null)
        {
            File.WriteAllText(Path.GetFullPath(outFilename), manifest);
            Console.WriteLine($"Manifest generated and saved to {Path.GetFullPath(outFilename)}");
        }
        else
        {
            Console.WriteLine("Failed to generate manifest. The manifest content is null.");
        }
    }
}