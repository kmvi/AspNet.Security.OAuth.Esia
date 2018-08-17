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
        }

        public string AccessType { get; set; } = "online";

        public Guid State { get; } = Guid.NewGuid();

        public X509Certificate2 ClientCertificate { get; set; }

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
    }
}
