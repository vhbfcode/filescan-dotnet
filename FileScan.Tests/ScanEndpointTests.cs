using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace FileScan.Tests;

/// <summary>Sobe o app com o ClamAV DESLIGADO — testa /scan ponta-a-ponta sem precisar de Docker.</summary>
public sealed class FileScanFactory : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureAppConfiguration((_, cfg) =>
            cfg.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["FileScan:ClamAv:Enabled"] = "false",
                ["FileScan:RateLimit:Enabled"] = "false",
            }));
    }
}

public class ScanEndpointTests(FileScanFactory factory) : IClassFixture<FileScanFactory>
{
    private readonly HttpClient _client = factory.CreateClient();

    private async Task<(HttpStatusCode Status, string? Verdict)> Scan(byte[] bytes, string fileName)
    {
        using var content = new MultipartFormDataContent { { new ByteArrayContent(bytes), "file", fileName } };
        var resp = await _client.PostAsync("/scan", content);

        string? verdict = null;
        if (resp.Content.Headers.ContentType?.MediaType == "application/json")
        {
            var json = await resp.Content.ReadFromJsonAsync<JsonElement>();
            if (json.TryGetProperty("verdict", out var v)) verdict = v.GetString();
        }
        return (resp.StatusCode, verdict);
    }

    [Fact]
    public async Task Health_IsOk()
        => Assert.Equal(HttpStatusCode.OK, (await _client.GetAsync("/health")).StatusCode);

    [Fact]
    public async Task Ready_IsOk_WhenClamAvDisabled()
        => Assert.Equal(HttpStatusCode.OK, (await _client.GetAsync("/ready")).StatusCode);

    [Fact]
    public async Task CleanPdf_ReturnsClean()
    {
        var (status, verdict) = await Scan(Samples.CleanPdf(), "ok.pdf");
        Assert.Equal(HttpStatusCode.OK, status);
        Assert.Equal("Clean", verdict);
    }

    [Fact]
    public async Task PdfWithJavaScript_ReturnsRejected()
        => Assert.Equal("Rejected", (await Scan(Samples.PdfWithJavaScript(), "evil.pdf")).Verdict);

    [Fact]
    public async Task PdfWithEmbeddedExecutable_ReturnsRejected()
        => Assert.Equal("Rejected", (await Scan(Samples.PdfWithEmbeddedExe(), "attach.pdf")).Verdict);

    [Fact]
    public async Task CsvInjection_ReturnsRejected()
        => Assert.Equal("Rejected", (await Scan(Samples.CsvInjection(), "data.csv")).Verdict);

    [Fact]
    public async Task NoFile_ReturnsBadRequest()
    {
        using var content = new MultipartFormDataContent { { new StringContent("x"), "notfile" } };
        var resp = await _client.PostAsync("/scan", content);
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }
}
