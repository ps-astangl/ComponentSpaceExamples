using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;

namespace ExampleServiceProvider.Controllers
{
    //
    // Demonstrates requiring JWT bearer tokens to authorize access to a web API.
    //
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    [Route("api/[controller]")]
    [ApiController]
    public class ClaimsController : ControllerBase
    {
        public class Claim
        {
            public string Type { get; set; }
            public string Value { get; set; }
        }

        [HttpGet]
        public IEnumerable<Claim> Get()
        {
            var claims = new List<Claim>();

            foreach (var claim in HttpContext.User.Claims)
            {
                claims.Add(new Claim()
                {
                    Type = claim.Type,
                    Value = claim.Value
                });
            }

            return claims;
        }
    }
}