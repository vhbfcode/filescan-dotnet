using FileScan.Scanning;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace FileScan.Controllers;

/// <summary>
/// Validação de arquivos: recebe um upload e devolve se é malicioso ou não.
/// </summary>
/// <remarks>
/// Contrato para quem chama: persistir o arquivo somente se <b>HTTP 200</b> e <c>verdict == "Clean"</c>.
/// Qualquer outra combinação (Malicious, Rejected, ou 503/Error) = não persistir (fail-closed).
/// </remarks>
[ApiController]
[Route("scan")]
[Produces("application/json")]
[EnableRateLimiting("scan")]
public sealed class ScanController(FileScanService scanner) : ControllerBase
{
    /// <summary>Valida um arquivo enviado em multipart/form-data (campo "file").</summary>
    /// <response code="200">Veredito definitivo: Clean, Malicious ou Rejected.</response>
    /// <response code="400">Nenhum arquivo enviado.</response>
    /// <response code="503">Não foi possível escanear (ex.: ClamAV indisponível) — falhe fechado.</response>
    [HttpPost]
    [Consumes("multipart/form-data")]
    [ProducesResponseType(typeof(ScanResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ScanResponse), StatusCodes.Status503ServiceUnavailable)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> Post(IFormFile? file, CancellationToken ct)
    {
        file ??= Request.Form.Files.FirstOrDefault();
        if (file is null || file.Length == 0)
            return BadRequest(new { error = "Envie um arquivo em multipart/form-data no campo 'file'." });

        await using var stream = file.OpenReadStream();
        var result = await scanner.ScanAsync(file.FileName, stream, file.Length, ct);

        // 200 quando há veredito definitivo; 503 quando não deu para escanear (caller falha fechado).
        return result.Verdict == ScanVerdict.Error
            ? StatusCode(StatusCodes.Status503ServiceUnavailable, result)
            : Ok(result);
    }
}
