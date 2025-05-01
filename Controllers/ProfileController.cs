using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;


namespace AxonFlow_Backend.Controllers;

[ApiController]
[Route("api/v1/[controller]")]
public class ProfileController : ControllerBase
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly SignInManager<IdentityUser> _signInManager;

    public ProfileController(
        UserManager<IdentityUser> userManager,
        SignInManager<IdentityUser> signInManager)
    {
        _userManager = userManager;
        _signInManager = signInManager;
    }
    
    public class UpdateNameRequest
    {
        [Required, EmailAddress]
        public string Email { get; set; }

        [Required]
        public string Password { get; set; }

        [Required]
        public string NewName { get; set; }
    }
    
    [HttpPost("update-name")]
    public async Task<IActionResult> UpdateUserName([FromBody] UpdateNameRequest request)
    {
        // 1. Find user by email
        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user == null)
        {
            return NotFound("User not found");
        }

        // 2. Verify password
        var passwordValid = await _userManager.CheckPasswordAsync(user, request.Password);
        if (!passwordValid)
        {
            return Unauthorized("Invalid credentials");
        }

        // 3. Update the username
        user.UserName = request.NewName; // Or add a Name property if you extended IdentityUser
        var result = await _userManager.UpdateAsync(user);

        if (!result.Succeeded)
        {
            return BadRequest(result.Errors);
        }

        return Ok(new { Message = "Name updated successfully" });
    }
}