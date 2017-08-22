using System;
using System.Diagnostics;
using System.Net.Http;
using System.Net.Security;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Extensions;
using Microsoft.IdentityModel.Protocols;

namespace AspNetCore.Authentication.WsFederation
{
    public class WsFederationPostConfigureOptions : IOptionsMonitor<WsFederationAuthenticationOptions>, IPostConfigureOptions<WsFederationAuthenticationOptions>
    {
        private readonly IDataProtectionProvider _dataProtectionProvider;

        public WsFederationAuthenticationOptions Get(string name)
        {
            return CurrentValue;
        }

        public IDisposable OnChange(Action<WsFederationAuthenticationOptions, string> listener)
        {
            throw new NotImplementedException();
        }

        public WsFederationAuthenticationOptions CurrentValue { get; private set; }

        public WsFederationPostConfigureOptions(
            IOptions<WsFederationAuthenticationOptions> options,
            IDataProtectionProvider dataProtectionProvider)
        {
            _dataProtectionProvider = dataProtectionProvider;
            ApplyDefaults(options.Value);
        }

        private void ApplyDefaults(WsFederationAuthenticationOptions wsFederationAuthenticationOptions)
        {
            if (string.IsNullOrEmpty(wsFederationAuthenticationOptions.SignInScheme))
            {
                throw new ArgumentException("Options.SignInScheme is required.");
            }
            var nextValue = new WsFederationAuthenticationOptions()
            {
                SignInScheme = wsFederationAuthenticationOptions.SignInScheme,
                TokenValidationParameters = wsFederationAuthenticationOptions.TokenValidationParameters,
                Configuration = wsFederationAuthenticationOptions.Configuration,
                ClaimsIssuer = wsFederationAuthenticationOptions.ClaimsIssuer,
                Backchannel = wsFederationAuthenticationOptions.Backchannel,
                BackchannelCertificateValidator = wsFederationAuthenticationOptions.BackchannelCertificateValidator,
                BackchannelHttpHandler = wsFederationAuthenticationOptions.BackchannelHttpHandler,
                BackchannelTimeout = wsFederationAuthenticationOptions.BackchannelTimeout,
                CallbackPath = wsFederationAuthenticationOptions.CallbackPath,
                ConfigurationManager = wsFederationAuthenticationOptions.ConfigurationManager,
                CorrelationCookie = wsFederationAuthenticationOptions.CorrelationCookie,
                DataProtectionProvider = wsFederationAuthenticationOptions.DataProtectionProvider,
                Events = wsFederationAuthenticationOptions.Events,//note the framework will call WsFederationAuthenticationHandler.CreateEventsAsync if this and EventsType is null
                EventsType = wsFederationAuthenticationOptions.EventsType,
                MetadataAddress = wsFederationAuthenticationOptions.MetadataAddress,
                RefreshOnIssuerKeyNotFound = wsFederationAuthenticationOptions.RefreshOnIssuerKeyNotFound,
                RemoteAuthenticationTimeout = wsFederationAuthenticationOptions.RemoteAuthenticationTimeout,
                SaveTokens = wsFederationAuthenticationOptions.SaveTokens,
                SecurityTokenHandlers = wsFederationAuthenticationOptions.SecurityTokenHandlers ??
                                        SecurityTokenHandlerCollectionExtensions.GetDefaultHandlers(),
                SignOutWreply = wsFederationAuthenticationOptions.SignOutWreply,
                SkipUnrecognizedRequests = wsFederationAuthenticationOptions.SkipUnrecognizedRequests,
                StateDataFormat = wsFederationAuthenticationOptions.StateDataFormat ?? new PropertiesDataFormat(
                                      _dataProtectionProvider.CreateProtector(
                                          typeof(WsFederationPostConfigureOptions).FullName,
                                          typeof(string).FullName,
                                          wsFederationAuthenticationOptions.SignInScheme,
                                          "v1"
                                      )),
                UseTokenLifetime = wsFederationAuthenticationOptions.UseTokenLifetime,
                Wreply = wsFederationAuthenticationOptions.Wreply,
                Wtrealm = wsFederationAuthenticationOptions.Wtrealm
            };

            if (string.IsNullOrWhiteSpace(nextValue.TokenValidationParameters.AuthenticationType))
            {
                nextValue.TokenValidationParameters.AuthenticationType = nextValue.SignInScheme;
            }
            if (string.IsNullOrWhiteSpace(nextValue.TokenValidationParameters.ValidAudience))
            {
                nextValue.TokenValidationParameters.ValidAudience = nextValue.Wtrealm;
            }


            Uri wreply;
            if (!nextValue.CallbackPath.HasValue && !string.IsNullOrEmpty(nextValue.Wreply) &&
                Uri.TryCreate(nextValue.Wreply, UriKind.Absolute, out wreply))
            {
                nextValue.CallbackPath = PathString.FromUriComponent(wreply);
            }

            if (nextValue.ConfigurationManager == null)
            {
                if (nextValue.Configuration != null)
                {
                    nextValue.ConfigurationManager =
                        new StaticConfigurationManager<WsFederationConfiguration>(nextValue.Configuration);
                }
                else
                {
                    var httpClient = new HttpClient(ResolveHttpMessageHandler(nextValue))
                    {
                        Timeout = nextValue.BackchannelTimeout,
                        MaxResponseContentBufferSize = 1024 * 1024 * 10
                    };
                    // 10 MB
                    nextValue.ConfigurationManager =
                        new ConfigurationManager<WsFederationConfiguration>(nextValue.MetadataAddress, httpClient);
                }
            }
            CurrentValue = nextValue;
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

        public void PostConfigure(string name, WsFederationAuthenticationOptions options)
        {
            ApplyDefaults(options);
        }
    }
}