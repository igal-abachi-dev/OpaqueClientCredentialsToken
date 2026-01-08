using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace OpaqueClientCredentialsTokenTester.Controllers
{
    [Route("api/[controller]")]
    [ApiController]

    public class OrdersController : ControllerBase
    {
        [HttpGet]
        //[Authorize(Policy = "orders.read")]
        public IActionResult GetOrders()
        {
            // 'User' is available as a property in ControllerBase
            var clientId = User.FindFirstValue(ClaimTypes.NameIdentifier) ?? User.FindFirstValue("client_id");
            var scopes = User.FindAll("scope").Select(c => c.Value).ToArray();

            return Ok(new
            {
                hello = "protected",
                clientId,
                scopes
            });
        }
    }
}