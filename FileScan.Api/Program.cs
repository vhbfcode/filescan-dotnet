using System.Reflection;
using System.Text.Json.Serialization;
using FileScan.Scanning;
using Microsoft.Extensions.Options;
using Microsoft.OpenApi;
using MimeDetective;
using MimeDetective.Definitions;
using nClam;
using Serilog;

var builder = WebApplication.CreateBuilder(args);

// --- Logging estruturado ---
builder.Host.UseSerilog((ctx, cfg) => cfg.ReadFrom.Configuration(ctx.Configuration));

// --- Controllers (rota /scan) com enums serializados como string ("Clean"/"Malicious"/...) ---
builder.Services.AddControllers()
    .AddJsonOptions(o => o.JsonSerializerOptions.Converters.Add(new JsonStringEnumConverter()));

// Endpoints mínimos (/health, /ready) também serializam enums como string.
builder.Services.ConfigureHttpJsonOptions(o =>
    o.SerializerOptions.Converters.Add(new JsonStringEnumConverter()));

// --- Swagger / OpenAPI ---
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(o =>
{
    o.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "FileScan",
        Version = "v1",
        Description = "Validador de arquivos: antimalware (ClamAV) + detecção de conteúdo ativo (injeção de script)."
    });

    var xml = Path.Combine(AppContext.BaseDirectory, $"{Assembly.GetExecutingAssembly().GetName().Name}.xml");
    if (File.Exists(xml)) o.IncludeXmlComments(xml);
});

// --- Opções (validadas no startup) ---
builder.Services.AddOptions<FileScanOptions>()
    .Bind(builder.Configuration.GetSection(FileScanOptions.SectionName))
    .ValidateDataAnnotations()
    .ValidateOnStart();

// --- Cliente ClamAV ---
builder.Services.AddSingleton<IClamClient>(sp =>
{
    var opt = sp.GetRequiredService<IOptions<FileScanOptions>>().Value;
    return new ClamClient(opt.ClamAv.Host, opt.ClamAv.Port)
    {
        MaxStreamSize = opt.MaxFileSizeBytes
    };
});

// Mime-Detective: detecção de tipo real por conteúdo (definições Default — livres p/ uso comercial).
builder.Services.AddSingleton<IContentInspector>(_ =>
    new ContentInspectorBuilder { Definitions = DefaultDefinitions.All() }.Build());

builder.Services.AddSingleton<StructuralValidator>();
builder.Services.AddSingleton<ClamAvScanner>();
builder.Services.AddSingleton<FileScanService>();

var app = builder.Build();

app.UseSerilogRequestLogging();

// --- Swagger UI em /swagger (servida antes do API key, para abrir no navegador) ---
// Em produção, considerar restringir a Development.
app.UseSwagger();
app.UseSwaggerUI(o =>
{
    o.SwaggerEndpoint("/swagger/v1/swagger.json", "FileScan v1");
    o.RoutePrefix = "swagger";
});

// --- Autenticação por API key (opcional: ligada quando FileScan:ApiKey estiver setada) ---
app.Use(async (context, next) =>
{
    var opt = context.RequestServices.GetRequiredService<IOptions<FileScanOptions>>().Value;
    var isPublic = context.Request.Path.StartsWithSegments("/health")
                   || context.Request.Path.StartsWithSegments("/ready");

    if (!isPublic && !string.IsNullOrEmpty(opt.ApiKey))
    {
        if (!context.Request.Headers.TryGetValue("X-Api-Key", out var key) || key != opt.ApiKey)
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }
    }

    await next();
});

// --- Liveness: o processo está de pé? ---
app.MapGet("/health", () => Results.Ok(new { status = "ok" }));

// --- Readiness: se o ClamAV estiver ligado, depende do clamd responder. ---
app.MapGet("/ready", async (ClamAvScanner scanner, IOptions<FileScanOptions> opt, CancellationToken ct) =>
{
    if (!opt.Value.ClamAv.Enabled)
        return Results.Ok(new { status = "ready", clamav = "disabled" });

    return await scanner.PingAsync(ct)
        ? Results.Ok(new { status = "ready" })
        : Results.Json(new { status = "clamav-unreachable" }, statusCode: StatusCodes.Status503ServiceUnavailable);
});

// --- Validação de arquivo: rota POST /scan em ScanController ---
app.MapControllers();

app.Run();

// Exposto para futuros testes de integração (WebApplicationFactory).
public partial class Program;
