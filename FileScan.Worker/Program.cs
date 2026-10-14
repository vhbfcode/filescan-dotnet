using FileScan.Scanning;

// stdout é EXCLUSIVO do protocolo: pega o fluxo bruto ANTES de redirecionar o Console.Out para o stderr,
// para que nenhum Console.WriteLine (nosso ou de biblioteca) corrompa o enquadramento.
var protocolOutput = Console.OpenStandardOutput();
var protocolInput = Console.OpenStandardInput();
Console.SetOut(Console.Error);

try
{
    return await WorkerHost.RunAsync(protocolInput, protocolOutput);
}
catch (Exception ex) when (ex is IOException or InvalidDataException or System.Text.Json.JsonException or EndOfStreamException)
{
    // Pai sumiu ou mandou lixo: encerra (o pai trata como falha de isolamento).
    Console.Error.WriteLine($"FileScan.Worker: protocolo interrompido ({ex.GetType().Name}: {ex.Message})");
    return 2;
}
