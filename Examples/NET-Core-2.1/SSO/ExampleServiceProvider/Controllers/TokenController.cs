using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace ExampleServiceProvider.Controllers
{
    //
    // Demonstrates generating a JWT bearer token for an authenticated user.
    //
    [Authorize]
    [Route("api/[controller]")]
    [ApiController]
    public class TokenController : ControllerBase
    {
        private readonly IConfiguration _configuration;

        public TokenController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [HttpGet]
        public IActionResult Get()
        {
            var claims = new List<Claim>();

            claims.Add(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()));
            claims.Add(new Claim(JwtRegisteredClaimNames.Sub, User.Identity.Name));

            var claim = User.FindFirst(ClaimTypes.Email);

            if (claim != null)
            {
                claims.Add(new Claim(JwtRegisteredClaimNames.Email, claim.Value));
            }

            claim = User.FindFirst(ClaimTypes.GivenName);

            if (claim != null)
            {
                claims.Add(new Claim(JwtRegisteredClaimNames.GivenName, claim.Value));
            }

            claim = User.FindFirst(ClaimTypes.Surname);

            if (claim != null)
            {
                claims.Add(new Claim(JwtRegisteredClaimNames.FamilyName, claim.Value));
            }

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Key"]));
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                _configuration["JWT:Issuer"],
                _configuration["JWT:Issuer"],
                claims,
                expires: DateTime.Now.AddHours(1),
                signingCredentials: credentials);

            return Ok(new { token = new JwtSecurityTokenHandler().WriteToken(token) });
        }
    }
}