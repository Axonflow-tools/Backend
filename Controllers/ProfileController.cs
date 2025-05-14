using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.ComponentModel.DataAnnotations;

namespace Backend.Controllers;

[ApiController]
[Route("api/v1/[controller]")]
public class ProfileController : ControllerBase
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly IConfiguration _config;

    public ProfileController(
        UserManager<IdentityUser> userManager,
        SignInManager<IdentityUser> signInManager,
        IConfiguration config)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _config = config;
    }

    // 1. Login Request DTO
    public class LoginRequest
    {
        [Required, EmailAddress]
        public string Email { get; set; }

        [Required]
        public string Password { get; set; }
    }

    // 2. Refresh Request DTO
    public class RefreshRequest
    {
        [Required]
        public string RefreshToken { get; set; }
    }

    // 3. Update Name DTO
    public class UpdateNameRequest
    {
        [Required, EmailAddress]
        public string Email { get; set; }

        [Required]
        public string Password { get; set; }

        [Required]
        public string NewName { get; set; }
    }

    // 4. LOGIN Endpoint
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user == null || !await _userManager.CheckPasswordAsync(user, request.Password))
            return Unauthorized("Invalid credentials");

        var accessToken = GenerateAccessToken(user);
        var refreshToken = GenerateRefreshToken();

        // TODO: Save refresh token if needed (optional)

        return Ok(new
        {
            accessToken,
            refreshToken,
            tokenType = "Bearer",
            expiresIn = 3600
        });
    }

    // 5. REFRESH Endpoint
    [HttpPost("refresh")]
    public IActionResult Refresh([FromBody] RefreshRequest request)
    {
        // ⚠️ Validate refresh token here (you can use DB or in-memory store)
        // For now, assume it’s valid

        var accessToken = GenerateAccessToken(new IdentityUser("placeholder")); // Replace with real user if needed
        var refreshToken = GenerateRefreshToken();

        return Ok(new
        {
            accessToken,
            refreshToken,
            tokenType = "Bearer",
            expiresIn = 3600
        });
    }

    // 6. UPDATE NAME Endpoint
    [HttpPost("update-name")]
    public async Task<IActionResult> UpdateUserName([FromBody] UpdateNameRequest request)
    {
        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user == null)
            return NotFound("User not found");

        if (!await _userManager.CheckPasswordAsync(user, request.Password))
            return Unauthorized("Invalid credentials");

        user.UserName = request.NewName;
        var result = await _userManager.UpdateAsync(user);

        if (!result.Succeeded)
            return BadRequest(result.Errors);

        return Ok(new { message = "Name updated successfully" });
    }

    // 7. Token Generator Helpers
    private string GenerateAccessToken(IdentityUser user)
    {
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id),
            new Claim(ClaimTypes.Email, user.Email ?? ""),
        };

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]!));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: _config["Jwt:Issuer"],
            audience: _config["Jwt:Audience"],
            claims: claims,
            expires: DateTime.UtcNow.AddHours(1),
            signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private string GenerateRefreshToken()
    {
        return Convert.ToBase64String(Guid.NewGuid().ToByteArray());
    }
}
