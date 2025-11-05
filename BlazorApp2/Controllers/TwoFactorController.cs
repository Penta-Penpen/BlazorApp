using BlazorApp2.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace BlazorApp2.Controllers
{
    [Authorize]
    [Route("api/account/2fa-remembered")]
    public class TwoFactorController : ControllerBase
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;

        public TwoFactorController(SignInManager<ApplicationUser> signInManager, UserManager<ApplicationUser> userManager)
        {
            _signInManager = signInManager;
            _userManager = userManager;
        }

        [HttpGet]
        public async Task<IActionResult> Get()
        {
            // ClaimsPrincipal -> アプリのユーザー実体を取得
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                // 未ログインやユーザーが見つからない場合は false を返す（もしくは 401 を返しても可）
                return Ok(false);
            }

            var remembered = await _signInManager.IsTwoFactorClientRememberedAsync(user);
            return Ok(remembered);
        }
    }
}
