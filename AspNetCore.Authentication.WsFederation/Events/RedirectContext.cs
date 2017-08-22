using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using AuthenticationProperties = Microsoft.AspNetCore.Http.Authentication.AuthenticationProperties;

namespace AspNetCore.Authentication.WsFederation
{
    public class RedirectContext : BaseWsFederationContext
    {
        public RedirectContext(HttpContext context, WsFederationAuthenticationOptions options, AuthenticationScheme authenticationScheme) : base(context, options, authenticationScheme)
        {
        }

        public AuthenticationProperties Properties { get; set; }
    }
}