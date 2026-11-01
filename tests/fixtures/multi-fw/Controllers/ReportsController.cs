[Route("api/[controller]")]
public class ReportsController : ControllerBase {
    [HttpGet("export")]
    public IActionResult Export() { return Ok(); }

    [Authorize(Roles = "Admin")]
    [HttpPost("purge")]
    public IActionResult Purge() { return Ok(); }
}
