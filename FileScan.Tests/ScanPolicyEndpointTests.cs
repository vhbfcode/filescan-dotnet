using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace FileScan.Tests;

public sealed class FlagPolicyFactory : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder) => Configure(builder, "Flag");

    internal static void Configure(IWebHostBuilder builder, string policy) =>
        builder.ConfigureAppConfiguration((_, configuration) =>
            configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["FileScan:ClamAv:Enabled"] = "false",
                ["FileScan:RateLimit:Enabled"] = "false",
                ["FileScan:ActiveContent:OnDetected"] = policy,
            }));
}

public sealed class IgnorePolicyFactory : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder) =>
        FlagPolicyFactory.Configure(builder, "Ignore");
}

public class ScanPolicyEndpointTests :
    IClassFixture<FlagPolicyFactory>, IClassFixture<IgnorePolicyFactory>
{
    private readonly HttpClient _flag;
    private readonly HttpClient _ignore;

    public ScanPolicyEndpointTests(FlagPolicyFactory flag, IgnorePolicyFactory ignore)
    {
        _flag = flag.CreateClient();
        _ignore = ignore.CreateClient();
    }

    [Fact]
    public async Task FlagPolicy_EndpointNeverSerializesActiveContentAsClean()
    {
        var result = await Scan(_flag, Samples.PdfWithJavaScript());
        Assert.Equal(HttpStatusCode.OK, result.Status);
        Assert.Equal("ActiveContentDetected", result.Verdict);
        Assert.Equal("filescan", result.Engine);
        Assert.True(result.HasWarnings);
    }

    [Fact]
    public async Task IgnorePolicy_EndpointNeverSerializesSkippedInspectionAsClean()
    {
        var result = await Scan(_ignore, Samples.PdfWithLzwFilteredStreamHidingJs());
        Assert.Equal(HttpStatusCode.OK, result.Status);
        Assert.Equal("NotInspected", result.Verdict);
        Assert.Equal("filescan", result.Engine);
        Assert.False(result.HasWarnings);
    }

    [Fact]
    public async Task FileSpecEfWithoutStreamType_EndpointNeverSerializesExecutableAsClean()
    {
        var result = await Scan(_flag, Samples.PdfWithFileSpecEfExecutable());
        Assert.Equal(HttpStatusCode.OK, result.Status);
        Assert.Equal("ActiveContentDetected", result.Verdict);
        Assert.Equal("filescan", result.Engine);
        Assert.True(result.HasWarnings);
    }

    private static async Task<(HttpStatusCode Status, string? Verdict, string? Engine, bool HasWarnings)>
        Scan(HttpClient client, byte[] bytes)
    {
        using var content = new MultipartFormDataContent
        {
            { new ByteArrayContent(bytes), "file", "x.pdf" },
        };
        using var response = await client.PostAsync("/scan", content);
        JsonElement json = await response.Content.ReadFromJsonAsync<JsonElement>();
        return (response.StatusCode,
            json.GetProperty("verdict").GetString(),
            json.GetProperty("engine").GetString(),
            json.TryGetProperty("warnings", out JsonElement warnings) && warnings.GetArrayLength() > 0);
    }
}
