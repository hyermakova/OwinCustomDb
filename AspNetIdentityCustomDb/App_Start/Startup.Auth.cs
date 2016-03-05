using System;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Owin;
using AspNetIdentityCustomDb.Models;
using Microsoft.Owin.Security.Google;
using Owin.Security.Providers.GitHub;
using Owin.Security.Providers.LinkedIn;
using System.Threading.Tasks;
using System.Configuration;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.WsFederation;

namespace AspNetIdentityCustomDb
{
    public partial class Startup
    {
        const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";

        // For more information on configuring authentication, please visit http://go.microsoft.com/fwlink/?LinkId=301864
        public void ConfigureAuth(IAppBuilder app)
        {
            string folderStorage = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "_Storage");

            // Configure the db context, user manager and signin manager to use a single instance per request
            // app.CreatePerOwinContext(ApplicationDbContext.Create);
            app.CreatePerOwinContext<Custom.Identity.UserManager>(() => new Custom.Identity.UserManager(new Custom.Identity.UserStore(folderStorage)));
            app.CreatePerOwinContext<Custom.Identity.RoleManager>(() => new Custom.Identity.RoleManager(new Custom.Identity.RoleStore(folderStorage)));
            app.CreatePerOwinContext<Custom.Identity.SignInService>((options, context) => new Custom.Identity.SignInService(context.GetUserManager<Custom.Identity.UserManager>(), context.Authentication));

            app.SetDefaultSignInAsAuthenticationType(WsFederationAuthenticationDefaults.AuthenticationType);

            // Enable the application to use a cookie to store information for the signed in user
            // and to use a cookie to temporarily store information about a user logging in with a third party login provider
            // Configure the sign in cookie
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                //ExpireTimeSpan
                AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                LoginPath = new PathString("/Account/Login"),
                Provider = new CookieAuthenticationProvider
                {
                    // Enables the application to validate the security stamp when the user logs in.
                    // This is a security feature which is used when you change a password or add an external login to your account.  
                    OnValidateIdentity = SecurityStampValidator.OnValidateIdentity<Custom.Identity.UserManager, Custom.Identity.User, string>(
                    validateInterval: TimeSpan.FromMinutes(30),
                    regenerateIdentityCallback: (manager, user) =>
                    {
                        var userIdentity = manager.CreateIdentityAsync(user, DefaultAuthenticationTypes.ApplicationCookie);
                        return (userIdentity);
                    },
                    getUserIdCallback: (id) => (id.GetUserId())
                    )
                }
            });

            app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);

            // Twitter : Create a new application
            // https://dev.twitter.com/apps
            if (!string.IsNullOrEmpty(ConfigurationManager.AppSettings.Get("TwitterConsumerKey")))
            {
                var twitterOptions = new Microsoft.Owin.Security.Twitter.TwitterAuthenticationOptions
                {
                    ConsumerKey = ConfigurationManager.AppSettings.Get("TwitterConsumerKey"),
                    ConsumerSecret = ConfigurationManager.AppSettings.Get("TwitterConsumerSecret"),
                    BackchannelCertificateValidator = new Microsoft.Owin.Security.CertificateSubjectKeyIdentifierValidator(new[]
                    {
                        "A5EF0B11CEC04103A34A659048B21CE0572D7D47", // VeriSign Class 3 Secure Server CA - G2
                        "0D445C165344C1827E1D20AB25F40163D8BE79A5", // VeriSign Class 3 Secure Server CA - G3
                        "7FD365A7C2DDECBBF03009F34339FA02AF333133", // VeriSign Class 3 Public Primary Certification Authority - G5
                        "39A55D933676616E73A761DFA16A7E59CDE66FAD", // Symantec Class 3 Secure Server CA - G4
                        "‎add53f6680fe66e383cbac3e60922e3b4c412bed", // Symantec Class 3 EV SSL CA - G3
                        "4eb6d578499b1ccf5f581ead56be3d9b6744a5e5", // VeriSign Class 3 Primary CA - G5
                        "5168FF90AF0207753CCCD9656462A212B859723B", // DigiCert SHA2 High Assurance Server C‎A 
                        "B13EC36903F8BF4701D498261A0802EF63642BC3" // DigiCert High Assurance EV Root CA
                    }),
                    Provider = new Microsoft.Owin.Security.Twitter.TwitterAuthenticationProvider
                    {
                        OnAuthenticated = (context) =>
                        {
                            context.Identity.AddClaim(new System.Security.Claims.Claim("urn:twitter:access_token", context.AccessToken, XmlSchemaString, "Twitter"));
                            return Task.FromResult(0);
                        }
                    }
                };

                app.UseTwitterAuthentication(twitterOptions);
            }

            // Facebook : Create New App
            // https://developers.facebook.com/apps
            if (!string.IsNullOrEmpty(ConfigurationManager.AppSettings.Get("FacebookAppId")))
            {
                var facebookOptions = new Microsoft.Owin.Security.Facebook.FacebookAuthenticationOptions
                {
                    AppId = ConfigurationManager.AppSettings.Get("FacebookAppId"),
                    AppSecret = ConfigurationManager.AppSettings.Get("FacebookAppSecret"),
                    Provider = new Microsoft.Owin.Security.Facebook.FacebookAuthenticationProvider
                    {
                        OnAuthenticated = (context) =>
                        {
                            context.Identity.AddClaim(new System.Security.Claims.Claim("urn:facebook:access_token", context.AccessToken, XmlSchemaString, "Facebook"));
                            foreach (var x in context.User)
                            {
                                var claimType = string.Format("urn:facebook:{0}", x.Key);
                                string claimValue = x.Value.ToString();
                                if (!context.Identity.HasClaim(claimType, claimValue))
                                    context.Identity.AddClaim(new System.Security.Claims.Claim(claimType, claimValue, XmlSchemaString, "Facebook"));

                            }
                            return Task.FromResult(0);
                        }
                    }
                };
                facebookOptions.Scope.Add("email");
                app.UseFacebookAuthentication(facebookOptions);
            }
        }
    }
}