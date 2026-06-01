using System.Net;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace FileScan.Tests;

/// <summary>App com rate limit baixo (2/janela) e ClamAV off — valida o 429 do /scan.</summary>
public sealed class RateLimitFactory : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureAppConfiguration((_, cfg) =>
            cfg.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["FileScan:ClamAv:Enabled"] = "false",
                ["FileScan:RateLimit:Enabled"] = "true",
                ["FileScan:RateLimit:PermitLimit"] = "2",
                ["FileScan:RateLimit:WindowSeconds"] = "60",
            }));
    }
}

public class RateLimitTests(RateLimitFactory factory) : IClassFixture<RateLimitFactory>
{
    private readonly RateLimitFactory _factory = factory;

    [Fact]
    public async Task Scan_ExceedingLimit_Returns429()
    {
        var client = _factory.CreateClient();

        async Task<HttpStatusCode> Post()
        {
            using var content = new MultipartFormDataContent { { new ByteArrayContent(Samples.CleanPdf()), "file", "ok.pdf" } };
            using var resp = await client.PostAsync("/scan", content);
            return resp.StatusCode;
        }

        Assert.Equal(HttpStatusCode.OK, await Post());            // 1
        Assert.Equal(HttpStatusCode.OK, await Post());            // 2
        Assert.Equal(HttpStatusCode.TooManyRequests, await Post()); // 3 → 429
    }
}
