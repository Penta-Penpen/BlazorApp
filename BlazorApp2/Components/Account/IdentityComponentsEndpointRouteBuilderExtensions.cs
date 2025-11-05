using BlazorApp2.Components.Account.Pages;
using BlazorApp2.Components.Account.Pages.Manage;
using BlazorApp2.Data;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;
using System.Security.Claims;
using System.Text;
using System.Text.Json;

namespace Microsoft.AspNetCore.Routing
{
    internal static class IdentityComponentsEndpointRouteBuilderExtensions
    {
        // These endpoints are required by the Identity Razor components defined in the /Components/Account/Pages directory of this project.
        public static IEndpointConventionBuilder MapAdditionalIdentityEndpoints(this IEndpointRouteBuilder endpoints)
        {
            ArgumentNullException.ThrowIfNull(endpoints);

            var accountGroup = endpoints.MapGroup("/Account");

            // ログインエンドポイントの追加.
            accountGroup.MapPost("/PerformLogin", async (
                HttpContext context,
                [FromServices] SignInManager<ApplicationUser> signInManager,
                [FromServices] ILogger<Program> logger,
                [FromForm] string Email,
                [FromForm] string Password,
                [FromForm] bool? RememberMe,
                [FromForm] string? ReturnUrl) =>
            {
                var result = await signInManager.PasswordSignInAsync(Email, Password, RememberMe ?? false, lockoutOnFailure: false);

                if (result.Succeeded)
                {
                    logger.LogInformation("User logged in.");
                    // Ensure ReturnUrl is local and safe
                    var redirectUrl = string.IsNullOrEmpty(ReturnUrl) ? "~/" : ReturnUrl;
                    if (!redirectUrl.StartsWith("~/") && !redirectUrl.StartsWith("/"))
                    {
                        redirectUrl = "~/";
                    }
                    return TypedResults.LocalRedirect(redirectUrl);
                }
                else if (result.RequiresTwoFactor)
                {
                    var redirectUrl = $"~/Account/LoginWith2fa?returnUrl={Uri.EscapeDataString(ReturnUrl ?? "")}&rememberMe={RememberMe ?? false}";
                    return TypedResults.LocalRedirect(redirectUrl);
                }
                else if (result.IsLockedOut)
                {
                    logger.LogWarning("User account locked out.");
                    return TypedResults.LocalRedirect("~/Account/Lockout");
                }
                else
                {
                    // エラーの場合は元のページにリダイレクト（エラーメッセージ付き）
                    var returnUrlWithError = $"~/Account/Login?error=Invalid login attempt&returnUrl={Uri.EscapeDataString(ReturnUrl ?? "")}";
                    return TypedResults.LocalRedirect(returnUrlWithError);
                }
            }).DisableAntiforgery();

            // 登録エンドポイントの追加.
            accountGroup.MapPost("/PerformRegister", async (
                HttpContext context,
                [FromServices] UserManager<ApplicationUser> userManager,
                [FromServices] IUserStore<ApplicationUser> userStore,
                [FromServices] SignInManager<ApplicationUser> signInManager,
                [FromServices] IEmailSender<ApplicationUser> emailSender,
                [FromServices] ILogger<Program> logger,
                [FromServices] NavigationManager navigationManager,
                [FromForm] string Email,
                [FromForm] string Password,
                [FromForm] string ConfirmPassword,
                [FromForm] string? ReturnUrl) =>
            {
                if (Password != ConfirmPassword)
                {
                    var errorUrl = $"~/Account/Register?error=Passwords do not match&returnUrl={Uri.EscapeDataString(ReturnUrl ?? "")}";
                    return TypedResults.LocalRedirect(errorUrl);
                }

                var user = Activator.CreateInstance<ApplicationUser>();
                await userStore.SetUserNameAsync(user, Email, CancellationToken.None);

                var emailStore = (IUserEmailStore<ApplicationUser>)userStore;
                await emailStore.SetEmailAsync(user, Email, CancellationToken.None);

                var result = await userManager.CreateAsync(user, Password);

                if (!result.Succeeded)
                {
                    var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                    var errorUrl = $"~/Account/Register?error={Uri.EscapeDataString(errors)}&returnUrl={Uri.EscapeDataString(ReturnUrl ?? "")}";
                    return TypedResults.LocalRedirect(errorUrl);
                }

                logger.LogInformation("User created a new account with password.");

                var userId = await userManager.GetUserIdAsync(user);
                var code = await userManager.GenerateEmailConfirmationTokenAsync(user);
                code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));

                var callbackUrl = $"{context.Request.Scheme}://{context.Request.Host}/Account/ConfirmEmail?userId={userId}&code={code}&returnUrl={Uri.EscapeDataString(ReturnUrl ?? "")}";

                await emailSender.SendConfirmationLinkAsync(user, Email, System.Text.Encodings.Web.HtmlEncoder.Default.Encode(callbackUrl));

                if (userManager.Options.SignIn.RequireConfirmedAccount)
                {
                    return TypedResults.LocalRedirect($"~/Account/RegisterConfirmation?email={Uri.EscapeDataString(Email)}&returnUrl={Uri.EscapeDataString(ReturnUrl ?? "")}");
                }

                await signInManager.SignInAsync(user, isPersistent: false);

                // Ensure ReturnUrl is local and safe
                var redirectUrl = string.IsNullOrEmpty(ReturnUrl) ? "~/" : ReturnUrl;
                if (!redirectUrl.StartsWith("~/") && !redirectUrl.StartsWith("/"))
                {
                    redirectUrl = "~/";
                }
                return TypedResults.LocalRedirect(redirectUrl);
            }).DisableAntiforgery();

            // 2FAログインエンドポイントの追加.
            accountGroup.MapPost("/PerformLoginWith2fa", async (
                HttpContext context,
                [FromServices] SignInManager<ApplicationUser> signInManager,
                [FromServices] UserManager<ApplicationUser> userManager,
                [FromServices] ILogger<Program> logger,
                [FromForm] string TwoFactorCode,
                [FromForm] string? RememberMe,
                [FromForm] bool? RememberMachine,
                [FromForm] string? ReturnUrl) =>
            {
                var user = await signInManager.GetTwoFactorAuthenticationUserAsync();
                if (user is null)
                {
                    return TypedResults.LocalRedirect("~/Account/Login?error=Unable to load two-factor authentication user");
                }

                bool rememberMe = false;
                if (!Boolean.TryParse(RememberMe, out rememberMe))
                    rememberMe = false;

                var authenticatorCode = TwoFactorCode.Replace(" ", string.Empty).Replace("-", string.Empty);
                var result = await signInManager.TwoFactorAuthenticatorSignInAsync(authenticatorCode, rememberMe, RememberMachine ?? false);
                var userId = await userManager.GetUserIdAsync(user);

                if (result.Succeeded)
                {
                    logger.LogInformation("User with ID '{UserId}' logged in with 2fa.", userId);

                    // Ensure ReturnUrl is local and safe
                    var redirectUrl = string.IsNullOrEmpty(ReturnUrl) ? "~/" : ReturnUrl;
                    if (!redirectUrl.StartsWith("~/") && !redirectUrl.StartsWith("/"))
                    {
                        redirectUrl = "~/";
                    }
                    return TypedResults.LocalRedirect(redirectUrl);
                }
                else if (result.IsLockedOut)
                {
                    logger.LogWarning("User with ID '{UserId}' account locked out.", userId);
                    return TypedResults.LocalRedirect("~/Account/Lockout");
                }
                else
                {
                    logger.LogWarning("Invalid authenticator code entered for user with ID '{UserId}'.", userId);
                    var errorUrl = $"~/Account/LoginWith2fa?error=Invalid authenticator code&returnUrl={Uri.EscapeDataString(ReturnUrl ?? "")}&rememberMe={RememberMe}";
                    return TypedResults.LocalRedirect(errorUrl);
                }
            }).DisableAntiforgery();

            // リカバリーコードログインエンドポイントの追加.
            accountGroup.MapPost("/PerformLoginWithRecoveryCode", async (
                HttpContext context,
                [FromServices] SignInManager<ApplicationUser> signInManager,
                [FromServices] UserManager<ApplicationUser> userManager,
                [FromServices] ILogger<Program> logger,
                [FromForm] string RecoveryCode,
                [FromForm] string? ReturnUrl) =>
            {
                var user = await signInManager.GetTwoFactorAuthenticationUserAsync();
                if (user is null)
                {
                    return TypedResults.LocalRedirect("~/Account/Login?error=Unable to load two-factor authentication user");
                }

                var recoveryCode = RecoveryCode.Replace(" ", string.Empty);
                var result = await signInManager.TwoFactorRecoveryCodeSignInAsync(recoveryCode);
                var userId = await userManager.GetUserIdAsync(user);

                if (result.Succeeded)
                {
                    logger.LogInformation("User with ID '{UserId}' logged in with a recovery code.", userId);

                    // Ensure ReturnUrl is local and safe
                    var redirectUrl = string.IsNullOrEmpty(ReturnUrl) ? "~/" : ReturnUrl;
                    if (!redirectUrl.StartsWith("~/") && !redirectUrl.StartsWith("/"))
                    {
                        redirectUrl = "~/";
                    }
                    return TypedResults.LocalRedirect(redirectUrl);
                }
                else if (result.IsLockedOut)
                {
                    logger.LogWarning("User account locked out.");
                    return TypedResults.LocalRedirect("~/Account/Lockout");
                }
                else
                {
                    logger.LogWarning("Invalid recovery code entered for user with ID '{UserId}'.", userId);
                    var errorUrl = $"~/Account/LoginWithRecoveryCode?error=Invalid recovery code entered&returnUrl={Uri.EscapeDataString(ReturnUrl ?? "")}";
                    return TypedResults.LocalRedirect(errorUrl);
                }
            }).DisableAntiforgery();

            // パスワード変更処理用エンドポイント.
            accountGroup.MapPost("/PerformChangePassword", async(
                HttpContext context,
                SignInManager<ApplicationUser> signInManager,
                [FromServices] UserManager<ApplicationUser> userManager,
                [FromServices] ILogger<Program> logger,
                [FromForm] string OldPassword,
                [FromForm] string NewPassword,
                [FromForm] string ConfirmPassword) =>
            {
                var user = await userManager.GetUserAsync(context.User);
                if (user is null)
                {
                    return Results.NotFound($"Unable to load user with ID '{userManager.GetUserId(context.User)}'.");
                }

                // パスワードの確認
                if (NewPassword != ConfirmPassword)
                {
                    var errorUrl = $"~/Account/Manage/ChangePassword?error={Uri.EscapeDataString("The new password and confirmation password do not match.")}";
                    return TypedResults.LocalRedirect(errorUrl);
                }

                // ユーザーがパスワードを持っているか確認
                var hasPassword = await userManager.HasPasswordAsync(user);
                if (!hasPassword)
                {
                    return TypedResults.LocalRedirect("~/Account/Manage/SetPassword");
                }

                // パスワード変更を実行
                var changePasswordResult = await userManager.ChangePasswordAsync(user, OldPassword, NewPassword);
                if (!changePasswordResult.Succeeded)
                {
                    var errors = string.Join(", ", changePasswordResult.Errors.Select(e => e.Description));
                    var errorUrl = $"~/Account/Manage/ChangePassword?error={Uri.EscapeDataString(errors)}";
                    return TypedResults.LocalRedirect(errorUrl);
                }


                await signInManager.RefreshSignInAsync(user);
                logger.LogInformation("User changed their password successfully.");

                var resultUrl = $"~/Account/Manage/ChangePassword?status={Uri.EscapeDataString("Your password has been changed.")}";
                return TypedResults.LocalRedirect(resultUrl);
            }).DisableAntiforgery();

            // 外部ログイン用エンドポイント.
            accountGroup.MapPost("/PerformExternalLogin", (
                HttpContext context,
                [FromServices] SignInManager<ApplicationUser> signInManager,
                [FromForm] string provider,
                [FromForm] string returnUrl) =>
            {
                IEnumerable<KeyValuePair<string, StringValues>> query = [
                    new("ReturnUrl", returnUrl),
                    new("Action", ExternalLogin.LoginCallbackAction)];

                var redirectUrl = UriHelper.BuildRelative(
                    context.Request.PathBase,
                    "/Account/ExternalLogin",
                    QueryString.Create(query));

                var properties = signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
                return TypedResults.Challenge(properties, [provider]);
            }).DisableAntiforgery();

            // 外部ログインコールバック処理用エンドポイント.
            accountGroup.MapGet("/PerformExternalLoginCallback", async (
                HttpContext context,
                [FromServices] SignInManager<ApplicationUser> signInManager,
                [FromServices] UserManager<ApplicationUser> userManager,
                [FromServices] IUserStore<ApplicationUser> userStore,
                [FromServices] IEmailSender<ApplicationUser> emailSender,
                [FromServices] ILogger<Program> logger,
                [FromQuery] string? returnUrl) =>
            {
                var info = await signInManager.GetExternalLoginInfoAsync();
                if (info is null)
                {
                    return TypedResults.LocalRedirect("~/Account/Login?error=Error loading external login information");
                }

                // Sign in the user with this external login provider if the user already has a login.
                var result = await signInManager.ExternalLoginSignInAsync(
                    info.LoginProvider,
                    info.ProviderKey,
                    isPersistent: false,
                    bypassTwoFactor: true);

                if (result.Succeeded)
                {
                    logger.LogInformation(
                        "{Name} logged in with {LoginProvider} provider.",
                        info.Principal.Identity?.Name,
                        info.LoginProvider);

                    // Ensure ReturnUrl is local and safe
                    var redirectUrl = string.IsNullOrEmpty(returnUrl) ? "~/" : returnUrl;
                    if (!redirectUrl.StartsWith("~/") && !redirectUrl.StartsWith("/"))
                    {
                        redirectUrl = "~/";
                    }
                    return TypedResults.LocalRedirect(redirectUrl);
                }
                else if (result.IsLockedOut)
                {
                    return TypedResults.LocalRedirect("~/Account/Lockout");
                }

                // If the user does not have an account, redirect back to registration page
                return TypedResults.LocalRedirect($"~/Account/ExternalLogin?returnUrl={Uri.EscapeDataString(returnUrl ?? "")}");
            });

            // 外部ログイン登録処理用エンドポイント.
            accountGroup.MapPost("/PerformExternalLoginRegister", async (
                HttpContext context,
                [FromServices] SignInManager<ApplicationUser> signInManager,
                [FromServices] UserManager<ApplicationUser> userManager,
                [FromServices] IUserStore<ApplicationUser> userStore,
                [FromServices] IEmailSender<ApplicationUser> emailSender,
                [FromServices] ILogger<Program> logger,
                [FromForm] string Email,
                [FromForm] string? ReturnUrl) =>
            {
                var info = await signInManager.GetExternalLoginInfoAsync();
                if (info is null)
                {
                    return TypedResults.LocalRedirect("~/Account/ExternalLogin?error=Error loading external login information");
                }

                var user = Activator.CreateInstance<ApplicationUser>();
                await userStore.SetUserNameAsync(user, Email, CancellationToken.None);

                var emailStore = (IUserEmailStore<ApplicationUser>)userStore;
                await emailStore.SetEmailAsync(user, Email, CancellationToken.None);

                var result = await userManager.CreateAsync(user);
                if (result.Succeeded)
                {
                    result = await userManager.AddLoginAsync(user, info);
                    if (result.Succeeded)
                    {
                        logger.LogInformation("User created an account using {Name} provider.", info.LoginProvider);

                        var userId = await userManager.GetUserIdAsync(user);
                        var code = await userManager.GenerateEmailConfirmationTokenAsync(user);
                        code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));

                        var callbackUrl = $"{context.Request.Scheme}://{context.Request.Host}/Account/ConfirmEmail?userId={userId}&code={code}";
                        await emailSender.SendConfirmationLinkAsync(user, Email, System.Text.Encodings.Web.HtmlEncoder.Default.Encode(callbackUrl));

                        // If account confirmation is required
                        if (userManager.Options.SignIn.RequireConfirmedAccount)
                        {
                            return TypedResults.LocalRedirect($"~/Account/RegisterConfirmation?email={Uri.EscapeDataString(Email)}&returnUrl={Uri.EscapeDataString(ReturnUrl ?? "")}");
                        }

                        await signInManager.SignInAsync(user, isPersistent: false, info.LoginProvider);

                        // Ensure ReturnUrl is local and safe
                        var redirectUrl = string.IsNullOrEmpty(ReturnUrl) ? "~/" : ReturnUrl;
                        if (!redirectUrl.StartsWith("~/") && !redirectUrl.StartsWith("/"))
                        {
                            redirectUrl = "~/";
                        }
                        return TypedResults.LocalRedirect(redirectUrl);
                    }
                }

                var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                return TypedResults.LocalRedirect($"~/Account/ExternalLogin?error={Uri.EscapeDataString(errors)}&returnUrl={Uri.EscapeDataString(ReturnUrl ?? "")}");
            }).DisableAntiforgery();

            // Resend Email Confirmation エンドポイント
            accountGroup.MapPost("/PerformResendEmailConfirmation", async (
                HttpContext context,
                [FromServices] UserManager<ApplicationUser> userManager,
                [FromServices] IEmailSender<ApplicationUser> emailSender,
                [FromForm] string? Email) =>
            {
                var user = await userManager.FindByEmailAsync(Email ?? "");
                if ((user is null) || (Email is null))
                {
                    return TypedResults.LocalRedirect("~/Account/ResendEmailConfirmation?status=" +
                        Uri.EscapeDataString("Verification email sent. Please check your email."));
                }

                var userId = await userManager.GetUserIdAsync(user);
                var code = await userManager.GenerateEmailConfirmationTokenAsync(user);
                code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));

                var callbackUrl = $"{context.Request.Scheme}://{context.Request.Host}/Account/ConfirmEmail?userId={userId}&code={code}";

                await emailSender.SendConfirmationLinkAsync(user, Email, System.Text.Encodings.Web.HtmlEncoder.Default.Encode(callbackUrl));

                return TypedResults.LocalRedirect("~/Account/ResendEmailConfirmation?status=" +
                    Uri.EscapeDataString("Verification email sent. Please check your email."));
            }).DisableAntiforgery();

            // Reset Password エンドポイント
            accountGroup.MapPost("/PerformResetPassword", async (
                HttpContext context,
                [FromServices] UserManager<ApplicationUser> userManager,
                [FromForm] string? Email,
                [FromForm] string? Password,
                [FromForm] string? ConfirmPassword,
                [FromForm] string? Code) =>
            {
                if (Password != ConfirmPassword)
                {
                    return TypedResults.LocalRedirect("~/Account/ResetPassword?code=" +
                        Uri.EscapeDataString(Code ?? "") + "&error=" +
                        Uri.EscapeDataString("Passwords do not match"));
                }

                var user = await userManager.FindByEmailAsync(Email ?? "");
                if (user is null)
                {
                    // Don't reveal that the user does not exist
                    return TypedResults.LocalRedirect("~/Account/ResetPasswordConfirmation");
                }

                var decodedCode = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(Code ?? ""));
                var result = await userManager.ResetPasswordAsync(user, decodedCode, Password ?? "");

                if (result.Succeeded)
                {
                    return TypedResults.LocalRedirect("~/Account/ResetPasswordConfirmation");
                }

                var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                return TypedResults.LocalRedirect("~/Account/ResetPassword?code=" +
                    Uri.EscapeDataString(Code ?? "") + "&error=" +
                    Uri.EscapeDataString(errors));
            }).DisableAntiforgery();

            // ログアウト処理用エンドポイント.
            accountGroup.MapPost("/Logout", async (
                ClaimsPrincipal user,
                SignInManager<ApplicationUser> signInManager,
                [FromForm] string returnUrl) =>
            {
                await signInManager.SignOutAsync();
                return TypedResults.LocalRedirect($"~/{returnUrl}");
            });

            var manageGroup = accountGroup.MapGroup("/Manage").RequireAuthorization();

            // Disable 2FA エンドポイント.
            manageGroup.MapPost("/PerformDisable2fa", async (
                HttpContext context,
                [FromServices] UserManager<ApplicationUser> userManager,
                [FromServices] ILogger<Program> logger) =>
            {
                var user = await userManager.GetUserAsync(context.User);
                if (user is null)
                {
                    return TypedResults.LocalRedirect("~/Account/Login");
                }

                var disable2faResult = await userManager.SetTwoFactorEnabledAsync(user, false);
                if (!disable2faResult.Succeeded)
                {
                    throw new InvalidOperationException("Unexpected error occurred disabling 2FA.");
                }

                var userId = await userManager.GetUserIdAsync(user);
                logger.LogInformation("User with ID '{UserId}' has disabled 2fa.", userId);

                return TypedResults.LocalRedirect("~/Account/Manage/TwoFactorAuthentication?status=" +
                    Uri.EscapeDataString("2fa has been disabled. You can reenable 2fa when you setup an authenticator app"));
            }).DisableAntiforgery();

            // Enable Authenticator エンドポイント.
            manageGroup.MapPost("/PerformEnableAuthenticator", async (
                HttpContext context,
                [FromServices] UserManager<ApplicationUser> userManager,
                [FromServices] ILogger<Program> logger,
                [FromForm] string Code) =>
            {
                var user = await userManager.GetUserAsync(context.User);
                if (user is null)
                {
                    return TypedResults.LocalRedirect("~/Account/Login");
                }

                // Strip spaces and hyphens
                var verificationCode = Code.Replace(" ", string.Empty).Replace("-", string.Empty);

                var is2faTokenValid = await userManager.VerifyTwoFactorTokenAsync(
                    user, userManager.Options.Tokens.AuthenticatorTokenProvider, verificationCode);

                if (!is2faTokenValid)
                {
                    return TypedResults.LocalRedirect("~/Account/Manage/EnableAuthenticator?error=" +
                        Uri.EscapeDataString("Verification code is invalid"));
                }

                await userManager.SetTwoFactorEnabledAsync(user, true);
                var userId = await userManager.GetUserIdAsync(user);
                logger.LogInformation("User with ID '{UserId}' has enabled 2FA with an authenticator app.", userId);

                if (await userManager.CountRecoveryCodesAsync(user) == 0)
                {
                    var recoveryCodes = await userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
                    var recoveryCodesStr = string.Join(",", recoveryCodes!);
                    return TypedResults.LocalRedirect("~/Account/Manage/EnableAuthenticator?recoveryCodes=" +
                        Uri.EscapeDataString(recoveryCodesStr));
                }
                else
                {
                    return TypedResults.LocalRedirect("~/Account/Manage/TwoFactorAuthentication?status=" +
                        Uri.EscapeDataString("Your authenticator app has been verified"));
                }
            }).DisableAntiforgery();

            // Reset Authenticator エンドポイント
            manageGroup.MapPost("/PerformResetAuthenticator", async (
                HttpContext context,
                [FromServices] UserManager<ApplicationUser> userManager,
                [FromServices] SignInManager<ApplicationUser> signInManager,
                [FromServices] ILogger<Program> logger) =>
            {
                var user = await userManager.GetUserAsync(context.User);
                if (user is null)
                {
                    return TypedResults.LocalRedirect("~/Account/Login");
                }

                await userManager.SetTwoFactorEnabledAsync(user, false);
                await userManager.ResetAuthenticatorKeyAsync(user);
                var userId = await userManager.GetUserIdAsync(user);
                logger.LogInformation("User with ID '{UserId}' has reset their authentication app key.", userId);

                await signInManager.RefreshSignInAsync(user);

                return TypedResults.LocalRedirect("~/Account/Manage/EnableAuthenticator?status=" +
                    Uri.EscapeDataString("Your authenticator app key has been reset, you will need to configure your authenticator app using the new key"));
            }).DisableAntiforgery();

            // Forget Browser エンドポイント
            manageGroup.MapPost("/PerformForgetBrowser", async (
                HttpContext context,
                [FromServices] SignInManager<ApplicationUser> signInManager) =>
            {
                await signInManager.ForgetTwoFactorClientAsync();

                return TypedResults.LocalRedirect("~/Account/Manage/TwoFactorAuthentication?status=" +
                    Uri.EscapeDataString("The current browser has been forgotten. When you login again from this browser you will be prompted for your 2fa code"));
            }).DisableAntiforgery();

            // Generate Recovery Codes エンドポイント
            manageGroup.MapPost("/PerformGenerateRecoveryCodes", async (
                HttpContext context,
                [FromServices] UserManager<ApplicationUser> userManager,
                [FromServices] ILogger<Program> logger) =>
            {
                var user = await userManager.GetUserAsync(context.User);
                if (user is null)
                {
                    return TypedResults.LocalRedirect("~/Account/Login");
                }

                var userId = await userManager.GetUserIdAsync(user);
                var recoveryCodes = await userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
                logger.LogInformation("User with ID '{UserId}' has generated new 2FA recovery codes.", userId);

                var recoveryCodesStr = string.Join(",", recoveryCodes!);
                return TypedResults.LocalRedirect("~/Account/Manage/GenerateRecoveryCodes?recoveryCodes=" +
                    Uri.EscapeDataString(recoveryCodesStr));
            }).DisableAntiforgery();

            // Delete Personal Data エンドポイント
            manageGroup.MapPost("/PerformDeletePersonalData", async (
                HttpContext context,
                [FromServices] UserManager<ApplicationUser> userManager,
                [FromServices] SignInManager<ApplicationUser> signInManager,
                [FromServices] ILogger<Program> logger,
                [FromForm] string? Password) =>
            {
                var user = await userManager.GetUserAsync(context.User);
                if (user is null)
                {
                    return Results.NotFound($"Unable to load user with ID '{userManager.GetUserId(context.User)}'.");
                }

                var requirePassword = await userManager.HasPasswordAsync(user);
                if (requirePassword && !await userManager.CheckPasswordAsync(user, Password ?? ""))
                {
                    var errorUrl = "~/Account/Manage/DeletePersonalData?error=Incorrect password";
                    return TypedResults.LocalRedirect(errorUrl);
                }

                var result = await userManager.DeleteAsync(user);
                if (!result.Succeeded)
                {
                    throw new InvalidOperationException("Unexpected error occurred deleting user.");
                }

                await signInManager.SignOutAsync();

                var userId = await userManager.GetUserIdAsync(user);
                logger.LogInformation("User with ID '{UserId}' deleted themselves.", userId);

                return TypedResults.LocalRedirect("~/");
            }).DisableAntiforgery();

            // Change Email エンドポイント
            manageGroup.MapPost("/PerformChangeEmail", async (
                HttpContext context,
                [FromServices] UserManager<ApplicationUser> userManager,
                [FromServices] IEmailSender<ApplicationUser> emailSender,
                [FromServices] NavigationManager navigationManager,
                [FromForm] string NewEmail) =>
            {
                var user = await userManager.GetUserAsync(context.User);
                if (user is null)
                {
                    return TypedResults.LocalRedirect("~/Account/Login");
                }

                var email = await userManager.GetEmailAsync(user);
                if (NewEmail == email)
                {
                    return TypedResults.LocalRedirect("~/Account/Manage/Email?status=" +
                        Uri.EscapeDataString("Your email is unchanged."));
                }

                var userId = await userManager.GetUserIdAsync(user);
                var code = await userManager.GenerateChangeEmailTokenAsync(user, NewEmail);
                code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));

                var callbackUrl = $"{context.Request.Scheme}://{context.Request.Host}/Account/ConfirmEmailChange?userId={userId}&email={Uri.EscapeDataString(NewEmail)}&code={code}";

                await emailSender.SendConfirmationLinkAsync(user, NewEmail, System.Text.Encodings.Web.HtmlEncoder.Default.Encode(callbackUrl));

                return TypedResults.LocalRedirect("~/Account/Manage/Email?status=" +
                    Uri.EscapeDataString("Confirmation link to change email sent. Please check your email."));
            }).DisableAntiforgery();

            // Update Profile エンドポイント
            manageGroup.MapPost("/PerformUpdateProfile", async (
                HttpContext context,
                [FromServices] UserManager<ApplicationUser> userManager,
                [FromServices] SignInManager<ApplicationUser> signInManager,
                [FromForm] string? PhoneNumber) =>
            {
                var user = await userManager.GetUserAsync(context.User);
                if (user is null)
                {
                    return TypedResults.LocalRedirect("~/Account/Login");
                }

                var phoneNumber = await userManager.GetPhoneNumberAsync(user);
                if (PhoneNumber != phoneNumber)
                {
                    var setPhoneResult = await userManager.SetPhoneNumberAsync(user, PhoneNumber);
                    if (!setPhoneResult.Succeeded)
                    {
                        return TypedResults.LocalRedirect("~/Account/Manage?status=" +
                            Uri.EscapeDataString("Error: Failed to set phone number."));
                    }
                }

                await signInManager.RefreshSignInAsync(user);

                return TypedResults.LocalRedirect("~/Account/Manage?status=" +
                    Uri.EscapeDataString("Your profile has been updated"));
            }).DisableAntiforgery();

            // Send Email Verification エンドポイント
            manageGroup.MapPost("/PerformSendEmailVerification", async (
                HttpContext context,
                [FromServices] UserManager<ApplicationUser> userManager,
                [FromServices] IEmailSender<ApplicationUser> emailSender) =>
            {
                var user = await userManager.GetUserAsync(context.User);
                if (user is null)
                {
                    return TypedResults.LocalRedirect("~/Account/Login");
                }

                var email = await userManager.GetEmailAsync(user);
                if (email is null)
                {
                    return TypedResults.LocalRedirect("~/Account/Manage/Email");
                }

                var userId = await userManager.GetUserIdAsync(user);
                var code = await userManager.GenerateEmailConfirmationTokenAsync(user);
                code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));

                var callbackUrl = $"{context.Request.Scheme}://{context.Request.Host}/Account/ConfirmEmail?userId={userId}&code={code}";

                await emailSender.SendConfirmationLinkAsync(user, email, System.Text.Encodings.Web.HtmlEncoder.Default.Encode(callbackUrl));

                return TypedResults.LocalRedirect("~/Account/Manage/Email?status=" +
                    Uri.EscapeDataString("Verification email sent. Please check your email."));
            }).DisableAntiforgery();

            // Set Password エンドポイント
            manageGroup.MapPost("/PerformSetPassword", async (
                HttpContext context,
                [FromServices] UserManager<ApplicationUser> userManager,
                [FromServices] SignInManager<ApplicationUser> signInManager,
                [FromServices] ILogger<Program> logger,
                [FromForm] string NewPassword,
                [FromForm] string ConfirmPassword) =>
            {
                var user = await userManager.GetUserAsync(context.User);
                if (user is null)
                {
                    return TypedResults.LocalRedirect("~/Account/Login");
                }

                if (NewPassword != ConfirmPassword)
                {
                    return TypedResults.LocalRedirect("~/Account/Manage/SetPassword?error=" +
                        Uri.EscapeDataString("Passwords do not match"));
                }

                var addPasswordResult = await userManager.AddPasswordAsync(user, NewPassword);
                if (!addPasswordResult.Succeeded)
                {
                    var errors = string.Join(", ", addPasswordResult.Errors.Select(e => e.Description));
                    return TypedResults.LocalRedirect("~/Account/Manage/SetPassword?error=" +
                        Uri.EscapeDataString(errors));
                }

                await signInManager.RefreshSignInAsync(user);
                logger.LogInformation("User set their password successfully.");

                return TypedResults.LocalRedirect("~/Account/Manage/SetPassword?status=" +
                    Uri.EscapeDataString("Your password has been set."));
            }).DisableAntiforgery();

            manageGroup.MapPost("/LinkExternalLogin", async (
                HttpContext context,
                [FromServices] SignInManager<ApplicationUser> signInManager,
                [FromForm] string provider) =>
            {
                // Clear the existing external cookie to ensure a clean login process
                await context.SignOutAsync(IdentityConstants.ExternalScheme);

                var redirectUrl = UriHelper.BuildRelative(
                    context.Request.PathBase,
                    "/Account/Manage/ExternalLogins",
                    QueryString.Create("Action", ExternalLogins.LinkLoginCallbackAction));

                var properties = signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl, signInManager.UserManager.GetUserId(context.User));
                return TypedResults.Challenge(properties, [provider]);
            });

            var loggerFactory = endpoints.ServiceProvider.GetRequiredService<ILoggerFactory>();
            var downloadLogger = loggerFactory.CreateLogger("DownloadPersonalData");

            // パーソナルデータ ダウンロード用エンドポイント.
            manageGroup.MapPost("/DownloadPersonalData", async (
                HttpContext context,
                [FromServices] UserManager<ApplicationUser> userManager,
                [FromServices] AuthenticationStateProvider authenticationStateProvider) =>
            {
                var user = await userManager.GetUserAsync(context.User);
                if (user is null)
                {
                    return Results.NotFound($"Unable to load user with ID '{userManager.GetUserId(context.User)}'.");
                }

                var userId = await userManager.GetUserIdAsync(user);
                downloadLogger.LogInformation("User with ID '{UserId}' asked for their personal data.", userId);

                // Only include personal data for download
                var personalData = new Dictionary<string, string>();
                var personalDataProps = typeof(ApplicationUser).GetProperties().Where(
                    prop => Attribute.IsDefined(prop, typeof(PersonalDataAttribute)));
                foreach (var p in personalDataProps)
                {
                    personalData.Add(p.Name, p.GetValue(user)?.ToString() ?? "null");
                }

                var logins = await userManager.GetLoginsAsync(user);
                foreach (var l in logins)
                {
                    personalData.Add($"{l.LoginProvider} external login provider key", l.ProviderKey);
                }

                personalData.Add("Authenticator Key", (await userManager.GetAuthenticatorKeyAsync(user))!);
                var fileBytes = JsonSerializer.SerializeToUtf8Bytes(personalData);

                context.Response.Headers.TryAdd("Content-Disposition", "attachment; filename=PersonalData.json");
                return TypedResults.File(fileBytes, contentType: "application/json", fileDownloadName: "PersonalData.json");
            }).DisableAntiforgery();

            return accountGroup;
        }
    }
}
