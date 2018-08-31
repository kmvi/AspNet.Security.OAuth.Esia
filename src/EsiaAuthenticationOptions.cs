using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Http;
using Newtonsoft.Json.Linq;

namespace AspNet.Security.OAuth.Esia
{
    public class EsiaAuthenticationOptions : OAuthOptions
    {
        public EsiaAuthenticationOptions()
        {
            CallbackPath = new PathString("/signin-esia");
            AuthorizationEndpoint = EsiaAuthenticationDefaults.AuthorizationEndpoint;
            TokenEndpoint = EsiaAuthenticationDefaults.TokenEndpoint;
            UserInformationEndpoint = EsiaAuthenticationDefaults.UserInformationEndpoint;

            Scope.Add(EsiaConstants.UserInformationScope);

            ClaimActions.MapJsonKey(ClaimTypes.DateOfBirth, "birthDate");
            ClaimActions.MapJsonKey(ClaimTypes.Gender, "gender");
            ClaimActions.MapJsonKey(ClaimTypes.GivenName, "firstName");
            ClaimActions.MapJsonKey(ClaimTypes.Surname, "lastName");
            ClaimActions.MapJsonKey(EsiaConstants.TrustedUrn, "trusted");
            ClaimActions.MapJsonKey(EsiaConstants.MiddleNameUrn, "middleName");
            ClaimActions.MapJsonKey(EsiaConstants.BirthPlaceUrn, "birthPlace");
            ClaimActions.MapJsonKey(EsiaConstants.CitizenshipUrn, "citizenship");
            ClaimActions.MapJsonKey(EsiaConstants.SnilsUrn, "snils");
            ClaimActions.MapJsonKey(EsiaConstants.InnUrn, "inn");
            ClaimActions.MapCustomJson(ClaimTypes.Name, ParseName);
            ClaimActions.MapCustomJson(ClaimTypes.Email, obj => ParseContactInfo(obj, "EML"));
            ClaimActions.MapCustomJson(ClaimTypes.MobilePhone, obj => ParseContactInfo(obj, "MBT"));
            ClaimActions.MapCustomJson(ClaimTypes.HomePhone, obj => ParseContactInfo(obj, "PHN"));
            ClaimActions.MapCustomJson(ClaimTypes.OtherPhone, obj => ParseContactInfo(obj, "CPH"));
        }

        public string AccessType { get; set; } = "online";

        public Guid State { get; } = Guid.NewGuid();

        public X509Certificate2 ClientCertificate { get; set; }

        public bool FetchContactInfo { get; set; } = false;

        public override void Validate()
        {
            try
            {
                base.Validate();
            }
            catch (ArgumentException e) when (e.ParamName == nameof(ClientSecret))
            {
                // Do nothing
            }
            catch (Exception)
            {
                throw;
            }
        }

        private static string ParseName(JObject obj)
        {
            var lastName = obj["lastName"]?.ToString();
            var firstName = obj["firstName"]?.ToString();
            var middleName = obj["middleName"]?.ToString();
            return String.Join(" ", new[] { lastName, firstName, middleName }.Where(x => !String.IsNullOrEmpty(x)));
        }

        private static string ParseContactInfo(JObject obj, string key)
        {
            return obj?.Value<JArray>("elements")?
                .FirstOrDefault(x => x["type"]?.ToString() == key)?["value"]?.ToString();
        }
    }
}
