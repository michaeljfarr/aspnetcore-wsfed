using System;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Protocols;

namespace AspNetCore.Authentication.WsFederation
{
    public class BaseWsFederationContext : HandleRequestContext<RemoteAuthenticationOptions>
    {
        public BaseWsFederationContext(HttpContext context, WsFederationAuthenticationOptions options, AuthenticationScheme authenticationScheme) :
            base(context, authenticationScheme, options)
        {
        }

        public WsFederationMessage ProtocolMessage { get; set; }
    }
}