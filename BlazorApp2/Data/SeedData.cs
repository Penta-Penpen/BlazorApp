using Microsoft.AspNetCore.Identity;

namespace BlazorApp2.Data
{
    public static class SeedData
    {
        public static async Task Initialize(IServiceProvider serviceProvider)
        {
            var context = serviceProvider.GetRequiredService<ApplicationDbContext>();
            var userManager = serviceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var roleManager = serviceProvider.GetRequiredService<RoleManager<IdentityRole>>();

            await context.Database.EnsureCreatedAsync();

            // ロール作成
            string[] roleNames = { "Administrator", "Operator", "User", "Guest" };
            foreach (var roleName in roleNames)
            {
                if (!await roleManager.RoleExistsAsync(roleName))
                {
                    await roleManager.CreateAsync(new IdentityRole(roleName));
                }
            }

            // テストユーザー作成
            //await CreateUserWithRole(userManager, "admin@example.com", "Admin123!", "管理者", "Admin");
            //await CreateUserWithRole(userManager, "moderator@example.com", "Moderator123!", "モデレーター", "Moderator");
            //await CreateUserWithRole(userManager, "user@example.com", "User123!", "一般ユーザー", "User");
            await CreateUserWithRole(userManager, "asaca_admin@asaca.co.jp", "Asaca_7!", "管理者", "Administrator");
            await CreateUserWithRole(userManager, "asaca_ope@asaca.co.jp", "Asaca_7!", "オペレーター", "Operator");
            await CreateUserWithRole(userManager, "asaca_user@asaca.co.jp", "Asaca_7!", "ユーザー", "User");
            await CreateUserWithRole(userManager, "asaca_guest@asaca.co.jp", "Asaca_7!", "ゲスト", "Guest");
        }

        private static async Task CreateUserWithRole(
            UserManager<ApplicationUser> userManager,
            string email,
            string password,
            string displayName,
            string role)
        {
            if (await userManager.FindByEmailAsync(email) == null)
            {
                var user = new ApplicationUser
                {
                    UserName = email,
                    Email = email,
                    DisplayName = displayName,
                    EmailConfirmed = true,
                };

                var result = await userManager.CreateAsync(user, password);
                if (result.Succeeded)
                {
                    await userManager.AddToRoleAsync(user, role);
                }
            }
        }
    }
}
