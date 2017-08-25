using System;
using System.Net.Http;
using System.Net.Security;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Extensions;
using Microsoft.IdentityModel.Protocols;

namespace AspNetCore.Authentication.WsFederation
{
    public class WsFederationPostConfigureOptions : IPostConfigureOptions<WsFederationAuthenticationOptions>
    {
        private readonly IDataProtectionProvider _dataProtectionProvider;
        private readonly ILogger<WsFederationPostConfigureOptions> _logger;

        public WsFederationPostConfigureOptions(IDataProtectionProvider dataProtectionProvider, ILogger<WsFederationPostConfigureOptions> logger)
        {
            _dataProtectionProvider = dataProtectionProvider;
            _logger = logger;
        }

        private void ApplyDefaults(WsFederationAuthenticationOptions wsFederationAuthenticationOptions)
        {
            _logger.LogTrace("ConfigureOptions start");
            ConfigureOptions(_dataProtectionProvider, wsFederationAuthenticationOptions);
            _logger.LogTrace($"ConfigureOptions complete, Audience: {wsFederationAuthenticationOptions?.TokenValidationParameters?.ValidAudience}, AuthType: {wsFederationAuthenticationOptions?.TokenValidationParameters?.AuthenticationType}, IsConfigurationManager not null:{wsFederationAuthenticationOptions?.ConfigurationManager != null}, CallbackPath {wsFederationAuthenticationOptions?.CallbackPath}");
        }
        public void PostConfigure(string name, WsFederationAuthenticationOptions options)
        {
            //SignInScheme will be provided by AuthenticationBuilder.EnsureSignInScheme if not provided by something else.
            //However, for reasons that I can't understand, this method always gets called with an uninitialised options and an empty name value
            //I'm guessing that is just a bug somewhere in the DefaultAuthorizationPolicyProvider when it attempts to fetch the default configuration.
            if (!string.IsNullOrEmpty(options.SignInScheme))
            {
                ApplyDefaults(options);
            }
        }

        private static void ConfigureOptions(IDataProtectionProvider dataProtectionProvider, WsFederationAuthenticationOptions wsFederationAuthenticationOptions)
        {
            if (string.IsNullOrEmpty(wsFederationAuthenticationOptions.SignInScheme))
            {
                throw new ArgumentException("Options.SignInScheme is required.");
            }


            wsFederationAuthenticationOptions.SecurityTokenHandlers =
                wsFederationAuthenticationOptions.SecurityTokenHandlers ??
                SecurityTokenHandlerCollectionExtensions.GetDefaultHandlers();
            wsFederationAuthenticationOptions.StateDataFormat =
                wsFederationAuthenticationOptions.StateDataFormat ?? new PropertiesDataFormat(
                    dataProtectionProvider.CreateProtector(
                        typeof(WsFederationPostConfigureOptions).FullName,
                        typeof(string).FullName,
                        wsFederationAuthenticationOptions.SignInScheme,
                        "v1"
                    ));
            wsFederationAuthenticationOptions.UseTokenLifetime = wsFederationAuthenticationOptions.UseTokenLifetime;
            wsFederationAuthenticationOptions.Wreply = wsFederationAuthenticationOptions.Wreply;
            wsFederationAuthenticationOptions.Wtrealm = wsFederationAuthenticationOptions.Wtrealm;

            if (string.IsNullOrWhiteSpace(wsFederationAuthenticationOptions.TokenValidationParameters.AuthenticationType))
            {
                wsFederationAuthenticationOptions.TokenValidationParameters.AuthenticationType = wsFederationAuthenticationOptions.SignInScheme;
            }
            if (string.IsNullOrWhiteSpace(wsFederationAuthenticationOptions.TokenValidationParameters.ValidAudience))
            {
                wsFederationAuthenticationOptions.TokenValidationParameters.ValidAudience = wsFederationAuthenticationOptions.Wtrealm;
            }


            Uri wreply;
            if (!wsFederationAuthenticationOptions.CallbackPath.HasValue && !string.IsNullOrEmpty(wsFederationAuthenticationOptions.Wreply) &&
                Uri.TryCreate(wsFederationAuthenticationOptions.Wreply, UriKind.Absolute, out wreply))
            {
                wsFederationAuthenticationOptions.CallbackPath = PathString.FromUriComponent(wreply);
            }

            if (wsFederationAuthenticationOptions.ConfigurationManager == null)
            {
                if (wsFederationAuthenticationOptions.Configuration != null)
                {
                    wsFederationAuthenticationOptions.ConfigurationManager =
                        new StaticConfigurationManager<WsFederationConfiguration>(wsFederationAuthenticationOptions.Configuration);
                }
                else
                {
                    var httpClient = new HttpClient(ResolveHttpMessageHandler(wsFederationAuthenticationOptions))
                    {
                        Timeout = wsFederationAuthenticationOptions.BackchannelTimeout,
                        MaxResponseContentBufferSize = 1024 * 1024 * 10
                    };
                    // 10 MB
                    wsFederationAuthenticationOptions.ConfigurationManager =
                        new ConfigurationManager<WsFederationConfiguration>(wsFederationAuthenticationOptions.MetadataAddress, httpClient);
                }
            }
        }

        private static HttpMessageHandler ResolveHttpMessageHandler(WsFederationAuthenticationOptions options)
        {
            var handler = options.BackchannelHttpHandler ?? new System.Net.Http.WebRequestHandler();

            // If they provided a validator, apply it or fail.
            if (options.BackchannelCertificateValidator != null)
            {
                // Set the cert validate callback
                var webRequestHandler = handler as WebRequestHandler;
                if (webRequestHandler == null)
                {
                    throw new InvalidOperationException(
                        "An BackchannelCertificateValidator cannot be specified at the same " +
                        "time as an HttpMessageHandler unless it is a WebRequestHandler.");
                }
                webRequestHandler.ServerCertificateValidationCallback =
                    new RemoteCertificateValidationCallback(options.BackchannelCertificateValidator);
            }

            return handler;
        }
    }
}