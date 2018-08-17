using System;
using System.Collections.Generic;
using System.Text;
using AspNet.Security.OAuth.Esia;
using Microsoft.AspNetCore.Authentication;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class EsiaAuthenticationExtensions
    {
        public static AuthenticationBuilder AddEsia(this AuthenticationBuilder builder)
            => builder.AddEsia(EsiaAuthenticationDefaults.AuthenticationScheme, _ => { });

        public static AuthenticationBuilder AddEsia(this AuthenticationBuilder builder, Action<EsiaAuthenticationOptions> configureOptions)
            => builder.AddEsia(EsiaAuthenticationDefaults.AuthenticationScheme, configureOptions);

        public static AuthenticationBuilder AddEsia(this AuthenticationBuilder builder, string authenticationScheme, Action<EsiaAuthenticationOptions> configureOptions)
            => builder.AddEsia(EsiaAuthenticationDefaults.AuthenticationScheme, EsiaAuthenticationDefaults.DisplayName, configureOptions);

        public static AuthenticationBuilder AddEsia(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<EsiaAuthenticationOptions> configureOptions)
            => builder.AddOAuth<EsiaAuthenticationOptions, EsiaAuthenticationHandler>(authenticationScheme, displayName, configureOptions);
    }
}
