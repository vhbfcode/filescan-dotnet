using FileScan.Scanning;

// Uso: FileScan.Tests.Child <pasta>  ->  "<arquivo>\t<veredito>" por PDF, em ordem, com flush a cada linha.
var directory = args[0];
var service = new FileScanService(new FileScannerOptions { AllowedExtensions = ["pdf"] });
foreach (var file in Directory.GetFiles(directory, "*.pdf").OrderBy(name => name, StringComparer.Ordinal))
{
    var response = await service.ScanAsync("x.pdf", File.ReadAllBytes(file));
    Console.WriteLine($"{Path.GetFileName(file)}\t{response.Verdict}");
    Console.Out.Flush();
}
