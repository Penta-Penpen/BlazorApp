using Microsoft.AspNetCore.Identity;

namespace BlazorApp2.Data
{
    // Add profile data for application users by adding properties to the ApplicationUser class
    public class ApplicationUser : IdentityUser
    {
        public string? DisplayName
        {
            get => _displayName;
            set => _displayName = value;
        }
        private string? _displayName;
    }

}
