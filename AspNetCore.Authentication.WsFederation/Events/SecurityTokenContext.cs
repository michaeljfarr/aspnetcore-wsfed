using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace AspNetCore.Authentication.WsFederation.Events
{
    public class SecurityTokenContext : BaseWsFederationContext
    {
        public SecurityTokenContext(HttpContext context, WsFederationAuthenticationOptions options, AuthenticationScheme authenticationScheme) : base(context, options, authenticationScheme)
        {
        }
    }
}