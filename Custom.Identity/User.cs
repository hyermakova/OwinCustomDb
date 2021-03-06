﻿using System;
using System.Linq;
using System.Collections.Generic;

namespace Custom.Identity
{
    using Microsoft.AspNet.Identity;

    public class User: IUser<string>
    {
        public User()
        {
            this.Roles = new List<string>();
            this.Claims = new List<UserClaim>();
            this.Logins = new List<UserLoginInfo>();
        }

        public User(string userName)
            : this()
        {
            this.UserName = userName;
        }

        public User(string id, string userName): this()
        {
            this.Id = Id;
            this.UserName = userName;
        }

        public string Id { get; set; }
        public string UserName { get; set; }
        public string PasswordHash { get; set; }

        public bool LockoutEnabled { get; set; }
        public DateTime? LockoutEndDateUtc { get; set; }
        public bool TwoFactorEnabled { get; set; }

        public IList<string> Roles { get; private set; }
        public IList<UserClaim> Claims { get; private set; }
        public List<UserLoginInfo> Logins { get; private set; }
    }
}
