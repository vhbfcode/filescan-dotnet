using System.Net;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace FileScan.Tests;

/// <summary>App com API key configurada (e ClamAV off) — valida a autenticação do /scan.</summary>
public sealed class AuthFactory : WebApplicationFactory<Program>
{
    public const string ApiKey = "s3cr3t-test-key";

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureAppConfiguration((_, cfg) =>
            cfg.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["FileScan:ClamAv:Enabled"] = "false",
                ["FileScan:RateLimit:Enabled"] = "false",
                ["FileScan:ApiKey"] = ApiKey,
            }));
    }
}

public class ScanAuthTests(AuthFactory factory) : IClassFixture<AuthFactory>
{
    private readonly AuthFactory _factory = factory;

    private static MultipartFormDataContent CleanFile()
        => new() { { new ByteArrayContent(Samples.CleanPdf()), "file", "ok.pdf" } };

    [Fact]
    public async Task Scan_WithoutApiKey_Is401()
    {
        using var resp = await _factory.CreateClient().PostAsync("/scan", CleanFile());
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task Scan_WithWrongApiKey_Is401()
    {
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Api-Key", "wrong-key");
        using var resp = await client.PostAsync("/scan", CleanFile());
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task Scan_WithCorrectApiKey_Is200()
    {
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Api-Key", AuthFactory.ApiKey);
        using var resp = await client.PostAsync("/scan", CleanFile());
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task Health_IsPublic_EvenWithApiKeyConfigured()
    {
        using var resp = await _factory.CreateClient().GetAsync("/health");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }
}
