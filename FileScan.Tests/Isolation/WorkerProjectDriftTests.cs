using System.Xml.Linq;
using Xunit;

namespace FileScan.Tests.Isolation;

/// <summary>
/// Canário de deriva: o FileScan.Worker COMPILA os fontes do Core, então precisa declarar as MESMAS dependências e
/// os mesmos itens de compilação que o Core; um pacote novo (ou um EmbeddedResource) só no Core compilaria o worker
/// sem ele e quebraria só em execução, dentro do processo filho.
/// </summary>
public class WorkerProjectDriftTests
{
    private static string Repo()
    {
        var tfm = new DirectoryInfo(AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar));
        return tfm.Parent!.Parent!.Parent!.Parent!.FullName;
    }

    private static XElement Load(string project) =>
        XDocument.Load(Path.Combine(Repo(), project, project + ".csproj")).Root!;

    private static string[] Items(XElement project, string item) =>
        [.. project.Descendants(item).Select(e => (e.Attribute("Include") ?? e.Attribute("Update"))!.Value).OrderBy(v => v, StringComparer.Ordinal)];

    [Fact]
    public void Worker_DeclaresEveryPackageReferenceOfTheCore()
    {
        var missing = Items(Load("FileScan.Core"), "PackageReference").Except(Items(Load("FileScan.Worker"), "PackageReference")).ToArray();
        Assert.True(missing.Length == 0, "o FileScan.Worker não declara as PackageReference do Core: " + string.Join(", ", missing));
    }

    [Fact]
    public void Core_HasNoItemsTheWorkerWouldSilentlyLose()
    {
        var core = Load("FileScan.Core");
        var worker = Load("FileScan.Worker");
        foreach (var kind in new[] { "EmbeddedResource", "AdditionalFiles", "Analyzer", "Compile" })
        {
            var coreOnly = Items(core, kind).Except(Items(worker, kind)).ToArray();
            Assert.True(coreOnly.Length == 0,
                $"o Core tem itens '{kind}' que o worker (que compila os fontes do Core) não replica: {string.Join(", ", coreOnly)}");
        }
    }

    [Fact]
    public void Worker_CompilesTheCoreSources_AndNeverReferencesTheCoreProject()
    {
        var worker = Load("FileScan.Worker");
        Assert.Contains(worker.Descendants("Compile"), e => (e.Attribute("Include")?.Value ?? "").Contains("FileScan.Core"));
        Assert.Empty(worker.Descendants("ProjectReference")); // um ProjectReference de volta ao Core é um ciclo de build
    }
}
