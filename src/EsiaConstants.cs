using System;
using System.Collections.Generic;
using System.Text;

namespace AspNet.Security.OAuth.Esia
{
    public static class EsiaConstants
    {
        internal static readonly string ContactsUrl = "ctts?embed=(elements)";

        public static readonly string AuthorizationUrl = "https://esia.gosuslugi.ru/aas/oauth2/ac";
        public static readonly string AccessTokenUrl = "https://esia.gosuslugi.ru/aas/oauth2/te";
        public static readonly string UserInformationUrl = "https://esia.gosuslugi.ru/rs/prns";

        public static readonly string TestAuthorizationUrl = "https://esia-portal1.test.gosuslugi.ru/aas/oauth2/ac";
        public static readonly string TestAccessTokenUrl = "https://esia-portal1.test.gosuslugi.ru/aas/oauth2/te";
        public static readonly string TestUserInformationUrl = "https://esia-portal1.test.gosuslugi.ru/rs/prns";

        public static readonly string UserInformationScope = "http://esia.gosuslugi.ru/usr_inf";

        public static readonly string SbjIdUrn = "urn:esia:sbj_id";
        public static readonly string TrustedUrn = "urn:esia:trusted";
        public static readonly string MiddleNameUrn = "urn:esia:middleName";
        public static readonly string BirthPlaceUrn = "urn:esia:birthPlace";
        public static readonly string CitizenshipUrn = "urn:esia:citizenship";
        public static readonly string SnilsUrn = "urn:esia:snils";
        public static readonly string InnUrn = "urn:esia:inn";
    }
}
