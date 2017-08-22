using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace AspNetCore.Authentication.WsFederation.Events
{
    public class SecurityTokenValidatedContext : BaseWsFederationContext
    {
        public SecurityTokenValidatedContext(HttpContext context, WsFederationAuthenticationOptions options, AuthenticationScheme authenticationScheme) : base(context, options, authenticationScheme)
        {
        }

        public AuthenticationTicket Ticket { get; set; }
    }
}