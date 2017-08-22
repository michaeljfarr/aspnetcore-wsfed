using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using AspNetCore.Authentication.WsFederation.Events;

namespace AspNetCore.Authentication.WsFederation
{
    /// <summary>
    /// Specifies events which the <see cref="WsFederationAuthenticationMiddleware"></see> invokes to enable developer control over the authentication process. />
    /// </summary>
    public class WsFederationEvents : RemoteAuthenticationEvents
    {

        /// <summary>
        /// Invoked to manipulate redirects to the identity provider for SignIn, SignOut, or Challenge.
        /// </summary>
        public Func<RedirectContext, Task> OnRedirectToIdentityProvider { get; set; } = context => TaskCache.CompletedTask;

        /// <summary>
        /// Invoked with the security token that has been extracted from the protocol message.
        /// </summary>
        public Func<SecurityTokenContext, Task> OnSecurityTokenReceived { get; set; } = context => TaskCache.CompletedTask;

        /// <summary>
        /// Invoked after the security token has passed validation and a ClaimsIdentity has been generated.
        /// </summary>
        public Func<SecurityTokenValidatedContext, Task> OnSecurityTokenValidated { get; set; } = context => TaskCache.CompletedTask;

        /// <summary>
        /// Invoked to manipulate redirects to the identity provider for SignIn, SignOut, or Challenge.
        /// </summary>
        public virtual Task RedirectToIdentityProvider(RedirectContext context)
        {
            return this.OnRedirectToIdentityProvider(context);
        }

        /// <summary>
        /// Invoked with the security token that has been extracted from the protocol message.
        /// </summary>
        public virtual Task SecurityTokenReceived(SecurityTokenContext context)
        {
            return this.OnSecurityTokenReceived(context);
        }

        /// <summary>
        /// Invoked after the security token has passed validation and a ClaimsIdentity has been generated.
        /// </summary>
        public virtual Task SecurityTokenValidated(SecurityTokenValidatedContext context)
        {
            return this.OnSecurityTokenValidated(context);
        }
    }
}