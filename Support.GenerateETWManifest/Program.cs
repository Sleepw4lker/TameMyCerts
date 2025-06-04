using System.Diagnostics.Tracing;
using System.Globalization;
using TameMyCerts;

// Generate the manifest
internal class Program
{
    private static void Main(string[] args)
    {
        string? outFilename = null;
        for (var i = 0; i < args.Length; i++)
        {
            if (args[i] != "--outfile" || i + 1 >= args.Length)
            {
                continue;
            }

            outFilename = args[i + 1];
            break;
        }

        // Validate the filename
        if (string.IsNullOrEmpty(outFilename))
        {
            throw new ArgumentException("Missing or invalid --outfile argument");
        }

        // This ensures the generates manifest uses the default en-US culture when the build process runs on a non-US operating system
        var cultureInfo = new CultureInfo("en-US");
        Thread.CurrentThread.CurrentCulture = cultureInfo;
        Thread.CurrentThread.CurrentUICulture = cultureInfo;

        // Generate the manifest
        var manifest = EventSource.GenerateManifest(typeof(ETWLogger), "TameMyCerts.Events.dll");

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