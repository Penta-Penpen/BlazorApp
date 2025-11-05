using BlazorApp2.Components;
using BlazorApp2.Components.Account;
using BlazorApp2.Data;
using BlazorApp2.Models;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using static Org.BouncyCastle.Math.EC.ECCurve;

// WebApplicationBuilder インスタンスを作成.
var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

// API コントローラー対応.
builder.Services.AddControllers();

// HttpClient を使うための設定.
builder.Services.AddHttpClient();

builder.Services.AddCascadingAuthenticationState();
builder.Services.AddScoped<IdentityUserAccessor>();
builder.Services.AddScoped<IdentityRedirectManager>();
builder.Services.AddScoped<AuthenticationStateProvider, IdentityRevalidatingAuthenticationStateProvider>();

// 認証サービスの設定.
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = IdentityConstants.ApplicationScheme;
    options.DefaultSignInScheme = IdentityConstants.ExternalScheme;
})
    .AddIdentityCookies();

// データベースの設定.
// NuGet から Microsoft.EntityFrameworkCore.Sqlite をインストールすること.
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlite(connectionString));
builder.Services.AddDatabaseDeveloperPageExceptionFilter();

// Identity の設定.
builder.Services.AddIdentityCore<ApplicationUser>(options =>
{
    options.SignIn.RequireConfirmedAccount = true;
    //    options.Password.RequireDigit = true;
    //    options.Password.RequireNonAlphanumeric = true;
    //    options.Password.RequireUppercase = true;
    //    options.Password.RequireLowercase = true;
    //    options.Password.RequiredLength = 8;
    //    // 次の行を付けることで 2FA が有効になる. でもなくてもいいらしい.
    //    options.Tokens.AuthenticatorTokenProvider = TokenOptions.DefaultAuthenticatorProvider;
})
    .AddRoles<IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddSignInManager()
    .AddDefaultTokenProviders();

// 確認用メール送信の設定.
#if true
// テンプレートで提供されるダミー.
builder.Services.AddSingleton<IEmailSender<ApplicationUser>, IdentityNoOpEmailSender>();
#else
// SMTP メールサーバーを使う場合は次を使う。.
// NuGetから MailKit (jstedfast/MailKit) をインストールすること.
builder.Services.Configure<SmtpEmailSenderOptions>(options =>
{
    options.ServerName = 
    options.PortNumber = 
    options.UseSsl = 
    options.UserName = 
    options.Password = 
    options.SenderName = 
    options.SenderAddress = 
});
builder.Services.AddSingleton<IEmailSender<ApplicationUser>, SmtpEmailSender>();
#endif

// 認可ポリシーの設定 (今回はグループっぽく使ってみる).
// 最後の 1 行は 2FA 認証を強制する時に使う.
builder.Services.AddAuthorizationBuilder()
    .AddPolicy("Administrators", policy => policy.RequireRole("Administrator"))
    .AddPolicy("Operators", policy => policy.RequireRole("Administrator", "Operator"))
    .AddPolicy("Users", policy => policy.RequireRole("Administrator", "Operator", "User"))
    .AddPolicy("AllUsers", policy => policy.RequireRole("Administrator", "Operator", "User", "Guest"));
    //.AddPolicy("Require2FA", policy => policy.RequireClaim("amr", "mfa"));

var app = builder.Build();

// データベース初期化、ロール／ユーザー作成.
using (IServiceScope scope = app.Services.CreateScope())
{
    IServiceProvider services = scope.ServiceProvider;

    // マイグレーションの代わりにデータベースを自動作成.
    var context = services.GetRequiredService<ApplicationDbContext>();
    context.Database.EnsureCreated();

    await SeedData.Initialize(services);
}

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseMigrationsEndPoint();
}
else
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseStaticFiles();
app.UseAntiforgery();

// API コントローラーを有効化.
app.MapControllers();

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

// Add additional endpoints required by the Identity /Account Razor components.
app.MapAdditionalIdentityEndpoints();

app.Run();
