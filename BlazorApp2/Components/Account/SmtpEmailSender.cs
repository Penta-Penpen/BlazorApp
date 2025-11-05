using BlazorApp2.Data;
using BlazorApp2.Models;
using MailKit.Net.Smtp;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using MimeKit;

namespace BlazorApp2.Components.Account
{
    public class SmtpEmailSender(IOptions<SmtpEmailSenderOptions> options, ILogger<SmtpEmailSender> logger) : IEmailSender<ApplicationUser>
    {
        private readonly ILogger _logger = logger;

        public SmtpEmailSenderOptions Options { get; } = options.Value;

        public async Task SendConfirmationLinkAsync(ApplicationUser user, string email, string confirmationLink)
        {
            await SendEmailAsync(email, "[VCX Web] Confirm your email",
                $"<html lang=\"en\"><head></head><body>Please confirm your account by <a href='{confirmationLink}'>clicking here</a>.</body></html>");
        }

        public async Task SendPasswordResetCodeAsync(ApplicationUser user, string email, string resetCode)
        {
            await SendEmailAsync(email, "[VCX Web] Reset your password",
                $"<html lang=\"en\"><head></head><body>Please reset your password $\"using the following code:<br>{resetCode}</body></html>");
        }

        public async Task SendPasswordResetLinkAsync(ApplicationUser user, string email, string resetLink)
        {
            await SendEmailAsync(email, "[VCX Web] Reset your password",
                $"<html lang=\"en\"><head></head><body>Please reset your password by $\"<a href='{resetLink}'>clicking here</a>.</body></html>");
        }

        /// <summary>メールを送信する.</summary>
        /// <param name="fromAddress">差出人.</param>
        /// <param name="toAddress">宛先.</param>
        /// <param name="subject">件名.</param>
        /// <param name="message">メッセージ.</param>
        /// <returns></returns>
        public async Task<Boolean> SendEmailAsync(String toAddress, String subject, String message)
        {
            String responce = "";

            try
            {
                MimeMessage mime_message = new MimeMessage();
                mime_message.From.Add(new MailboxAddress(Options.SenderName, Options.SenderAddress));
                mime_message.To.Add(new MailboxAddress(toAddress, toAddress));
                mime_message.Subject = subject;
                mime_message.Body = new TextPart("html") { Text = message, };
                using (SmtpClient client = new SmtpClient())
                {
                    await client.ConnectAsync(Options.ServerName, Options.PortNumber, Options.UseSsl);
                    if (Options.UseSsl)
                        await client.AuthenticateAsync(Options.UserName, Options.Password);
                    responce = await client.SendAsync(mime_message);
                    await client.DisconnectAsync(true);
                }
            }
            catch (Exception ex)
            {
                responce = "";
                System.Diagnostics.Debug.WriteLine("SmtpEmailSender.SendEmailAsync(), 例外, " + ex.Message);
            }

            return ((3 <= responce.Length) && (('2' == responce[0]) || ('3' == responce[0])));
        }

    }
}
