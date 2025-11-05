namespace BlazorApp2.Models
{
    /// <summary>SMTP 電子メール送信のオプション.</summary>
    public class SmtpEmailSenderOptions
    {
        /// <summary>サーバー名.</summary>
        public String? ServerName { get; set; }

        /// <summary>ポート番号.</summary>
        public Int32 PortNumber { get; set; }

        /// <summary>ユーザー名.</summary>
        public String? UserName { get; set; }

        /// <summary>SSL を使用するか.</summary>
        public Boolean UseSsl { get; set; } = false;

        /// <summary>パスワード.</summary>
        public String? Password { get; set; }

        /// <summary>差出人アドレス.</summary>
        public String? SenderAddress { get; set; }

        /// <summary>差出人名.</summary>
        public String? SenderName { get; set; }

    }
}
