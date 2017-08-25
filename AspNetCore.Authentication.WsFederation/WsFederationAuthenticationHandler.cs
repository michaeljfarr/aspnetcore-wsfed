using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Security;
using System.Text.Encodings.Web;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using AspNetCore.Authentication.WsFederation.Events;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Extensions;
using Microsoft.IdentityModel.Protocols;

namespace AspNetCore.Authentication.WsFederation
{
    public class WsFederationAuthenticationHandler : RemoteAuthenticationHandler<WsFederationAuthenticationOptions>, IAuthenticationSignOutHandler
    {
        public WsFederationAuthenticationHandler(IOptionsMonitor<WsFederationAuthenticationOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock)
            : base(options, logger, encoder, clock)
        {
        }

        private async Task<WsFederationConfiguration> GetWsFederationConfiguration()
        {
            if (Options.Configuration == null && Options.ConfigurationManager == null)
            {
                Logger.LogCritical("Configuration and ConfigurationManager are both null.  WsFederationPostConfigureOptions should at least configure ConfigurationManager.");
            }
            if (Options.ConfigurationManager != null)
            {
                //in theory ConfigurationManager is caching and refreshing this data appropriately, so we dont need to hold on to an instance of this.
                var configuration = await Options.ConfigurationManager.GetConfigurationAsync(CancellationToken.None);
                return configuration;
            }
            return Options.Configuration;
        }


        /// <summary>
        /// First the Options.Events value is checked
        /// Then a service with Options.EventsType is checked
        /// then if neither is non-null, this method is called
        /// </summary>
        protected override Task<object> CreateEventsAsync()
        {
            return Task.FromResult<object>(new WsFederationEvents());
        }


        public override Task<bool> ShouldHandleRequestAsync()
        {
            return Task.FromResult<bool>(Options.CallbackPath.HasValue && Options.CallbackPath.Equals(Request.Path, StringComparison.OrdinalIgnoreCase));
        }

        /// <summary>
        ///     Authenticate the user identity with the identity provider.
        ///     The method process the request on the endpoint defined by CallbackPath.
        /// </summary>
        protected override async Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
        {
            // Allow login to be constrained to a specific path.
            if (!await ShouldHandleRequestAsync())
            //if (Options.CallbackPath.HasValue && !Options.CallbackPath.Equals(Request.Path, StringComparison.OrdinalIgnoreCase))
            {
                // Not for us.
                Logger.LogDebug($"Skipping {Options.CallbackPath} != {Request.Path}");
                return HandleRequestResult.SkipHandler();
            }

            WsFederationMessage wsFederationMessage = null;

            // assumption: if the ContentType is "application/x-www-form-urlencoded" it should be safe to read as it is small.
            if (string.Equals(Request.Method, "POST", StringComparison.OrdinalIgnoreCase)
                && !string.IsNullOrWhiteSpace(Request.ContentType)
                // May have media/type; charset=utf-8, allow partial match.
                &&
                Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase)
                && Request.Body.CanRead)
            {
                if (!Request.Body.CanSeek)
                {
                    Logger.LogDebug("Buffering request body");
                    // Buffer in case this body was not meant for us.
                    var memoryStream = new MemoryStream();
                    await Request.Body.CopyToAsync(memoryStream);
                    memoryStream.Seek(0, SeekOrigin.Begin);
                    Request.Body = memoryStream;
                }
                var form = await Request.ReadFormAsync();
                Request.Body.Seek(0, SeekOrigin.Begin);

                // TODO: a delegate on WsFederationAuthenticationOptions would allow for users to hook their own custom message.
                wsFederationMessage = new WsFederationMessage(
                    form.Select(pair => new KeyValuePair<string, string[]>(pair.Key, pair.Value.ToArray())));
            }

            if (wsFederationMessage == null || !wsFederationMessage.IsSignInMessage)
            {
                if (Options.SkipUnrecognizedRequests)
                {
                    // Not for us?
                    return HandleRequestResult.SkipHandler();
                }
                return HandleRequestResult.Fail("No message");
            }

            try
            {
                if (wsFederationMessage.Wresult == null)
                {
                    return HandleRequestResult.Fail("Received a sign-in message without a WResult.");
                }

                var token = wsFederationMessage.GetToken();
                if (string.IsNullOrWhiteSpace(token))
                {
                    return HandleRequestResult.Fail("Received a sign-in message without a token.");
                }

                var securityTokenContext = await RunSecurityTokenReceivedEventAsync(wsFederationMessage);
                if (securityTokenContext.Result?.Handled == true)
                {
                    return HandleRequestResult.Success(securityTokenContext.Result.Ticket);
                }

                var configuration = await GetWsFederationConfiguration();

                if (configuration == null)
                {
                    return HandleRequestResult.Fail("Configuration Missing.");
                }

                // Copy and augment to avoid cross request race conditions for updated configurations.
                var tvp = Options.TokenValidationParameters.Clone();
                IEnumerable<string> issuers = new[] { configuration.Issuer };
                tvp.ValidIssuers = tvp.ValidIssuers?.Concat(issuers) ?? issuers;
                tvp.IssuerSigningKeys = tvp.IssuerSigningKeys?.Concat(configuration.SigningKeys) ??
                                        configuration.SigningKeys;


                SecurityToken parsedToken;
                var principal = Options.SecurityTokenHandlers.ValidateToken(token, tvp, out parsedToken);

                if (!string.IsNullOrEmpty(Options.BootStrapTokenClaimName) && parsedToken != null)
                {
                    var identity = principal.Identity as System.Security.Claims.ClaimsIdentity;
                    if (identity != null)
                    {
                        var sb = new System.Text.StringBuilder();
                        var writer = System.Xml.XmlWriter.Create(new StringWriter(sb), new System.Xml.XmlWriterSettings
                        {
                            OmitXmlDeclaration = true
                        });
                        Options.SecurityTokenHandlers[parsedToken].WriteToken(writer, parsedToken);
                        writer.Flush();
                        identity.AddClaim(new System.Security.Claims.Claim(Options.BootStrapTokenClaimName, Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(sb.ToString()))));
                    }
                }
                // Retrieve our cached redirect uri
                var state = wsFederationMessage.Wctx;
                // WsFed allows for uninitiated logins, state may be missing.
                var properties = GetPropertiesFromWctx(state);
                var ticket = new AuthenticationTicket(principal, properties, Scheme.Name);

                if (Options.UseTokenLifetime)
                {
                    // Override any session persistence to match the token lifetime.
                    var issued = parsedToken.ValidFrom;
                    if (issued != DateTime.MinValue)
                    {
                        ticket.Properties.IssuedUtc = issued.ToUniversalTime();
                    }
                    var expires = parsedToken.ValidTo;
                    if (expires != DateTime.MinValue)
                    {
                        ticket.Properties.ExpiresUtc = expires.ToUniversalTime();
                    }
                    ticket.Properties.AllowRefresh = false;
                }

                var securityTokenValidatedNotification = await RunSecurityTokenValidatedEventAsync(wsFederationMessage,
                    ticket);
                if (securityTokenValidatedNotification.Result != null && securityTokenValidatedNotification.Result.Handled)
                {
                    return HandleRequestResult.Success(securityTokenValidatedNotification.Result.Ticket);
                }
                return HandleRequestResult.Success(ticket);
            }
            catch (Exception exception)
            {
                Logger.LogError("Exception occurred while processing message: ", exception);

                // Refresh the configuration for exceptions that may be caused by key rollovers. The user can also request a refresh in the notification.
                if (Options.RefreshOnIssuerKeyNotFound &&
                    exception.GetType() == typeof(SecurityTokenSignatureKeyNotFoundException))
                {
                    Options.ConfigurationManager.RequestRefresh();
                }

                var authenticationFailedNotification = await RunAuthenticationFailedEventAsync(wsFederationMessage,
                    exception);

                if (authenticationFailedNotification.Result != null && authenticationFailedNotification.Result.Handled)
                {
                    return HandleRequestResult.Fail(authenticationFailedNotification.Result.Failure);
                }
                return HandleRequestResult.Fail(exception);
            }
        }

        /// <inheritdoc />
        protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            if (properties == null)
            {
                throw new ArgumentNullException(nameof(properties));
            }
            Logger.LogTrace($"Entering {nameof(WsFederationAuthenticationHandler)}'s HandleUnauthorizedAsync");


            var baseUri =
                Request.Scheme +
                Uri.SchemeDelimiter +
                Request.Host +
                Request.PathBase;

            var currentUri =
                baseUri +
                Request.Path +
                Request.QueryString;

            if (string.IsNullOrEmpty(properties.RedirectUri))
            {
                properties.RedirectUri = currentUri;
            }

            var configuration = await GetWsFederationConfiguration();
            if (configuration == null)
            {
                this.Response.StatusCode = 401;
                return ;
            }
            var wsFederationMessage = new WsFederationMessage
            {
                IssuerAddress = configuration.TokenEndpoint ?? string.Empty,
                Wtrealm = Options.Wtrealm,
                Wctx =
                    $"{WsFederationAuthenticationDefaults.WctxKey}={Uri.EscapeDataString(Options.StateDataFormat.Protect(properties))}",
                Wa = WsFederationActions.SignIn,
                Wreply = BuildWreply(Options.CallbackPath)
            };

            if (!string.IsNullOrWhiteSpace(Options.Wreply))
            {
                wsFederationMessage.Wreply = Options.Wreply;
            }

            var redirectContext = new RedirectContext(Context, Options, Scheme)
            {
                ProtocolMessage = wsFederationMessage,
                Properties = new Microsoft.AspNetCore.Http.Authentication.AuthenticationProperties(properties.Items)
            };

            await Options.WsFedEvents.RedirectToIdentityProvider(redirectContext);
            if (redirectContext.Result != null && redirectContext.Result.Handled)
            {
                Logger.LogDebug("RedirectContext.HandledResponse");
            }
            if (redirectContext.Result == null || redirectContext.Result.None)
            {
                Logger.LogDebug("RedirectContext.Skipped");
            }

            var redirectUri = redirectContext.ProtocolMessage.CreateSignInUrl();
            if (!Uri.IsWellFormedUriString(redirectUri, UriKind.Absolute))
            {
                Logger.LogWarning($"The sign-in redirect URI is malformed: {redirectUri}");
            }
            Response.Redirect(redirectUri);
        }

        /// <inheritdoc />
        public async Task SignOutAsync(AuthenticationProperties properties)
        {

            if (properties == null)
            {
                return;
            }

            Logger.LogTrace($"Entering {nameof(WsFederationAuthenticationHandler)}'s HandleSignOutAsync");

            var configuration = await GetWsFederationConfiguration();
            if (configuration == null)
            {
                return;
            }

            var wsFederationMessage = new WsFederationMessage
            {
                IssuerAddress = configuration.TokenEndpoint ?? string.Empty,
                Wtrealm = Options.Wtrealm,
                Wa = WsFederationActions.SignOut
            };

            if (!string.IsNullOrEmpty(properties?.RedirectUri))
            {
                wsFederationMessage.Wreply = properties.RedirectUri;
            }
            else if (!string.IsNullOrWhiteSpace(Options.SignOutWreply))
            {
                wsFederationMessage.Wreply = Options.SignOutWreply;
            }
            else if (!string.IsNullOrWhiteSpace(Options.Wreply))
            {
                wsFederationMessage.Wreply = Options.Wreply;
            }

            var redirectContext = new RedirectContext(Context, Options, Scheme)
            {
                ProtocolMessage = wsFederationMessage
            };
            await Options.WsFedEvents.RedirectToIdentityProvider(redirectContext);
            if (redirectContext.Result != null && redirectContext.Result.Handled)
            {
                Logger.LogDebug("RedirectContext.HandledResponse");
                return;
            }
            if (redirectContext.Result != null && redirectContext.Result.Skipped)
            {
                Logger.LogDebug("RedirectContext.Skipped");
                return;
            }

            var redirectUri = redirectContext.ProtocolMessage.CreateSignOutUrl();
            if (!Uri.IsWellFormedUriString(redirectUri, UriKind.Absolute))
            {
                Logger.LogWarning($"The sign-out redirect URI is malformed: {redirectUri}");
            }
            Response.Redirect(redirectUri);
        }

        private AuthenticationProperties GetPropertiesFromWctx(string state)
        {
            AuthenticationProperties properties = null;
            if (!string.IsNullOrEmpty(state))
            {
                var pairs = ParseDelimited(state);
                List<string> values;
                if (pairs.TryGetValue(WsFederationAuthenticationDefaults.WctxKey, out values) && values.Count > 0)
                {
                    var value = values.First();
                    properties = Options.StateDataFormat.Unprotect(value);
                }
            }
            return properties;
        }

        private async Task<SecurityTokenContext> RunSecurityTokenReceivedEventAsync(WsFederationMessage message)
        {
            Logger.LogTrace($"SecurityTokenReceived: {message.GetToken()}");
            var securityTokenContext = new SecurityTokenContext(Context, Options, Scheme)
            {
                ProtocolMessage = message
            };

            await Options.WsFedEvents.SecurityTokenReceived(securityTokenContext);
            if (securityTokenContext.Result != null && securityTokenContext.Result.Handled)
            {
                Logger.LogDebug("SecurityTokenContext.HandledResponse");
            }
            else if (securityTokenContext.Result == null || securityTokenContext.Result.None)
            {
                Logger.LogDebug("SecurityTokenContext.Skipped");
            }

            return securityTokenContext;
        }

        private async Task<SecurityTokenValidatedContext> RunSecurityTokenValidatedEventAsync(
            WsFederationMessage message,
            AuthenticationTicket ticket)
        {
            Logger.LogTrace($"SecurityTokenValidated: {ticket.AuthenticationScheme} {ticket.Principal.Identity.Name}");
            var securityTokenValidateContext = new SecurityTokenValidatedContext(Context, Options, Scheme)
            {
                ProtocolMessage = message,
                Ticket = ticket
            };

            await Options.WsFedEvents.SecurityTokenValidated(securityTokenValidateContext);

            if (securityTokenValidateContext.Result != null && securityTokenValidateContext.Result.Handled)
            {
                Logger.LogDebug("SecurityTokenValidatedContext.HandledResponse");
            }
            else if (securityTokenValidateContext.Result == null || securityTokenValidateContext.Result.None)
            {
                Logger.LogDebug("SecurityTokenValidatedContext.Skipped");
            }

            return securityTokenValidateContext;
        }

        private async Task<RemoteFailureContext> RunAuthenticationFailedEventAsync(WsFederationMessage message,
            Exception exception)
        {
            Logger.LogTrace("AuthenticationFailed");
            var authenticationFailedContext = new RemoteFailureContext(Context, this.Scheme, Options, exception);

            await Options.Events.OnRemoteFailure(authenticationFailedContext);
            if (authenticationFailedContext.Result != null && authenticationFailedContext.Result.Handled)
            {
                Logger.LogDebug("AuthenticationFailedContext.HandledResponse");
            }
            else if (authenticationFailedContext.Result == null || authenticationFailedContext.Result.None)
            {
                Logger.LogDebug("AuthenticationFailedContext.Skipped");
            }

            return authenticationFailedContext;
        }

        private string BuildWreply(string targetPath)
        {
            return Request.Scheme + "://" + Request.Host + OriginalPathBase + targetPath;
        }

        private static IDictionary<string, List<string>> ParseDelimited(string text)
        {
            char[] delimiters = { '&', ';' };
            var accumulator = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
            var textLength = text.Length;
            var equalIndex = text.IndexOf('=');
            if (equalIndex == -1)
            {
                equalIndex = textLength;
            }
            var scanIndex = 0;
            while (scanIndex < textLength)
            {
                var delimiterIndex = text.IndexOfAny(delimiters, scanIndex);
                if (delimiterIndex == -1)
                {
                    delimiterIndex = textLength;
                }
                if (equalIndex < delimiterIndex)
                {
                    while (scanIndex != equalIndex && char.IsWhiteSpace(text[scanIndex]))
                        ++scanIndex;
                    var name = text.Substring(scanIndex, equalIndex - scanIndex);
                    var value = text.Substring(equalIndex + 1, delimiterIndex - equalIndex - 1);

                    name = Uri.UnescapeDataString(name.Replace('+', ' '));
                    value = Uri.UnescapeDataString(value.Replace('+', ' '));

                    List<string> existing;
                    if (!accumulator.TryGetValue(name, out existing))
                    {
                        accumulator.Add(name, new List<string>(1) { value });
                    }
                    else
                    {
                        existing.Add(value);
                    }

                    equalIndex = text.IndexOf('=', delimiterIndex);
                    if (equalIndex == -1)
                    {
                        equalIndex = textLength;
                    }
                }
                scanIndex = delimiterIndex + 1;
            }
            return accumulator;
        }
    }
}