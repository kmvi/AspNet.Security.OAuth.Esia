using System;
using System.Collections.Generic;
using System.Text;

namespace AspNet.Security.OAuth.Esia
{
    public static class EsiaAuthenticationDefaults
    {
        public const string AuthenticationScheme = "ESIA";
        public static readonly string DisplayName = "ЕСИА";
        public static readonly string AuthorizationEndpoint = EsiaConstants.AuthorizationUrl;
        public static readonly string TokenEndpoint = EsiaConstants.AccessTokenUrl;
        public static readonly string UserInformationEndpoint = EsiaConstants.UserInformationUrl;
    }
}
