using System;
using System.Collections.Generic;
using System.Linq;

namespace Custom.Identity
{
    using System.Threading.Tasks;
    using Microsoft.AspNet.Identity;

    public class UserManager : UserManager<User, string>
    {
        public UserManager(IUserStore<User, string> store): base(store)
        {
            this.UserLockoutEnabledByDefault = false;
            // this.DefaultAccountLockoutTimeSpan = TimeSpan.FromMinutes(10);
            // this.MaxFailedAccessAttemptsBeforeLockout = 10;
            this.UserValidator = new UserValidator<User, string>(this)
            {
                AllowOnlyAlphanumericUserNames = false,
                RequireUniqueEmail = false
            };

            // Configure validation logic for passwords
            this.PasswordValidator = new PasswordValidator
            {
                RequiredLength = 4,
                RequireNonLetterOrDigit = false,
                RequireDigit = false,
                RequireLowercase = false,
                RequireUppercase = false,
            };

        }

    }

}
