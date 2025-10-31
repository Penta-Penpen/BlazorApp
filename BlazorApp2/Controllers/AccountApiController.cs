using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

// NOTE: If your project uses a custom ApplicationUser type, replace IdentityUser with that type.
public class LoginDto
{
    public string Email { get; set; }
    public string Password { get; set; }
    public bool RememberMe { get; set; }
    public string ReturnUrl { get; set; }
}

[ApiController]
[Route("api/[controller]")]
public class AccountApiController : ControllerBase
{
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly UserManager<IdentityUser> _userManager;

    public AccountApiController(SignInManager<IdentityUser> signInManager, UserManager<IdentityUser> userManager)
    {
        _signInManager = signInManager;
        _userManager = userManager;
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginDto model)
    {
        if (model == null) return BadRequest(new { error = "Missing payload" });

        var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, lockoutOnFailure: false);
        if (result.Succeeded)
        {
            // Cookie is issued here because this runs inside an HTTP request context.
            return Ok(new { redirect = string.IsNullOrEmpty(model.ReturnUrl) ? "/" : model.ReturnUrl });
        }
        if (result.IsLockedOut)
        {
            return Forbid();
        }
        return Unauthorized(new { error = "Invalid credentials" });
    }

    [HttpPost("logout")]
    public async Task<IActionResult> Logout()
    {
        await _signInManager.SignOutAsync();
        return Ok();
    }

    // Start external login (Challenge). Navigate the browser to this URL (forceLoad=true from Blazor)
    [HttpGet("externallogin")]
    public IActionResult ExternalLogin([FromQuery] string provider, [FromQuery] string returnUrl = "/")
    {
        var redirectUrl = Url.Action(nameof(ExternalLoginCallback), "AccountApi", new { returnUrl });
        var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
        return Challenge(properties, provider);
    }

    // External login callback
    [HttpGet("externallogincallback")]
    public async Task<IActionResult> ExternalLoginCallback([FromQuery] string returnUrl = "/")
    {
        var info = await _signInManager.GetExternalLoginInfoAsync();
        if (info == null)
        {
            return Redirect(returnUrl);
        }

        var signInResult = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false);
        if (signInResult.Succeeded)
        {
            return Redirect(returnUrl);
        }

        // If user doesn't exist, optional: create user and sign in
        var email = info.Principal.FindFirstValue(ClaimTypes.Email);
        if (!string.IsNullOrEmpty(email))
        {
            var user = new IdentityUser { UserName = email, Email = email };
            var createResult = await _userManager.CreateAsync(user);
            if (createResult.Succeeded)
            {
                await _userManager.AddLoginAsync(user, info);
                await _signInManager.SignInAsync(user, isPersistent: false);
                return Redirect(returnUrl);
            }
        }

        return Redirect(returnUrl);
    }
}
