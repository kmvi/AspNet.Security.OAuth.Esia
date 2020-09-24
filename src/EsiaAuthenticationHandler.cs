using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using System.Globalization;
using System.Web;
using System.Text.Json;

using Base64UrlTextEncoder = Microsoft.AspNetCore.Authentication.Base64UrlTextEncoder;

namespace AspNet.Security.OAuth.Esia
{
    public class EsiaAuthenticationHandler : OAuthHandler<EsiaAuthenticationOptions>
    {
        public EsiaAuthenticationHandler(
            IOptionsMonitor<EsiaAuthenticationOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock)
            : base(options, logger, encoder, clock)
        {
        }

        protected override string BuildChallengeUrl(AuthenticationProperties properties, string redirectUri)
        {
            var secret = new EsiaClientSecret(Options);
            Options.ClientSecret = secret.GenerateClientSecret();

            var queryStrings = new Dictionary<string, string>
            {
                { "response_type", "code" },
                { "client_id", Options.ClientId },
                { "redirect_uri", redirectUri },
                { "scope", secret.Scope },
                { "access_type", Options.AccessType },
                { "state", secret.State },
                { "client_secret", Options.ClientSecret },
                { "timestamp", secret.Timestamp },
            };

            var authorizationEndpoint = QueryHelpers.AddQueryString(Options.AuthorizationEndpoint, queryStrings);

            return authorizationEndpoint;
        }

        protected override async Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
        {
            var query = Request.Query;
            var properties = Options.StateDataFormat.Unprotect(query["data"]);
            if (properties == null)
            {
                return HandleRequestResult.Fail("The return data was missing or invalid.");
            }

            // OAuth2 10.12 CSRF
            if (!ValidateCorrelationId(properties))
            {
                return HandleRequestResult.Fail("Correlation failed.", properties);
            }

            string state = query["state"];
            if (state != Options.State.ToString("D"))
            {
                return HandleRequestResult.Fail("The oauth state was missing or invalid.");
            }

            var error = query["error"];
            if (!StringValues.IsNullOrEmpty(error))
            {
                var failureMessage = new StringBuilder();
                failureMessage.Append(error);
                var errorDescription = query["error_description"];
                if (!StringValues.IsNullOrEmpty(errorDescription))
                {
                    failureMessage.Append(";Description=").Append(errorDescription);
                }
                var errorUri = query["error_uri"];
                if (!StringValues.IsNullOrEmpty(errorUri))
                {
                    failureMessage.Append(";Uri=").Append(errorUri);
                }

                return HandleRequestResult.Fail(failureMessage.ToString(), properties);
            }

            var code = query["code"];
            if (StringValues.IsNullOrEmpty(code))
            {
                return HandleRequestResult.Fail("Code was not found.", properties);
            }

            var context = new OAuthCodeExchangeContext(properties, code, BuildRedirectUri(Options.CallbackPath));
            var tokens = await ExchangeCodeAsync(context);

            if (tokens.Error != null)
            {
                return HandleRequestResult.Fail(tokens.Error, properties);
            }

            if (string.IsNullOrEmpty(tokens.AccessToken))
            {
                return HandleRequestResult.Fail("Failed to retrieve access token.", properties);
            }

            var identity = new ClaimsIdentity(ClaimsIssuer);
            if (Options.SaveTokens)
            {
                var authTokens = new List<AuthenticationToken>();

                authTokens.Add(new AuthenticationToken { Name = "access_token", Value = tokens.AccessToken });
                if (!string.IsNullOrEmpty(tokens.RefreshToken))
                {
                    authTokens.Add(new AuthenticationToken { Name = "refresh_token", Value = tokens.RefreshToken });
                }

                if (!string.IsNullOrEmpty(tokens.TokenType))
                {
                    authTokens.Add(new AuthenticationToken { Name = "token_type", Value = tokens.TokenType });
                }

                if (!string.IsNullOrEmpty(tokens.ExpiresIn))
                {
                    int value;
                    if (int.TryParse(tokens.ExpiresIn, NumberStyles.Integer, CultureInfo.InvariantCulture, out value))
                    {
                        // https://www.w3.org/TR/xmlschema-2/#dateTime
                        // https://msdn.microsoft.com/en-us/library/az4se3k1(v=vs.110).aspx
                        var expiresAt = Clock.UtcNow + TimeSpan.FromSeconds(value);
                        authTokens.Add(new AuthenticationToken
                        {
                            Name = "expires_at",
                            Value = expiresAt.ToString("o", CultureInfo.InvariantCulture)
                        });
                    }
                }

                properties.StoreTokens(authTokens);
            }

            var ticket = await CreateTicketAsync(identity, properties, tokens);
            if (ticket != null)
            {
                return HandleRequestResult.Success(ticket);
            }
            else
            {
                return HandleRequestResult.Fail("Failed to retrieve user information from remote server.", properties);
            }
        }

        protected override async Task<OAuthTokenResponse> ExchangeCodeAsync(OAuthCodeExchangeContext context)
        {
            var secret = new EsiaClientSecret(Options);
            Options.ClientSecret = secret.GenerateClientSecret();

            var requestParam = new Dictionary<string, string>
            {
                { "client_id", Options.ClientId },
                { "code", context.Code },
                { "grant_type", "authorization_code" },
                { "state", secret.State },
                { "scope", secret.Scope },
                { "timestamp", secret.Timestamp },
                { "token_type", "Bearer" },
                { "client_secret", Options.ClientSecret },
                { "redirect_uri", context.RedirectUri }
            };

            var request = new HttpRequestMessage(HttpMethod.Post, Options.TokenEndpoint);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            request.Content = new FormUrlEncodedContent(requestParam);

            var response = await Backchannel.SendAsync(request, Context.RequestAborted);
            if (response.IsSuccessStatusCode)
            {
                var payload = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
                return OAuthTokenResponse.Success(payload);
            }
            else
            {
                var error = "OAuth token endpoint failure: " + await Display(response);
                return OAuthTokenResponse.Failed(new Exception(error));
            }
        }

        private static async Task<string> Display(HttpResponseMessage response)
        {
            var output = new StringBuilder();
            output.Append("Status: " + response.StatusCode + ";");
            output.Append("Headers: " + response.Headers.ToString() + ";");
            output.Append("Body: " + await response.Content.ReadAsStringAsync() + ";");
            return output.ToString();
        }

        protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            if (string.IsNullOrEmpty(properties.RedirectUri))
            {
                properties.RedirectUri = CurrentUri;
            }

            // OAuth2 10.12 CSRF
            GenerateCorrelationId(properties);

            var redirectUri = BuildRedirectUri(Options.CallbackPath);
            var builder = new UriBuilder(redirectUri);
            var query = HttpUtility.ParseQueryString(builder.Query);
            query["data"] = Options.StateDataFormat.Protect(properties);
            builder.Query = query.ToString();

            var authorizationEndpoint = BuildChallengeUrl(properties, builder.ToString());
            var redirectContext = new RedirectContext<OAuthOptions>(
                Context, Scheme, Options,
                properties, authorizationEndpoint);
            await Events.RedirectToAuthorizationEndpoint(redirectContext);
        }

        protected override async Task<AuthenticationTicket> CreateTicketAsync(
            ClaimsIdentity identity, AuthenticationProperties properties, OAuthTokenResponse tokens)
        {
            string sbjId = GetSubjectId(tokens);
            identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, sbjId));
            identity.AddClaim(new Claim(EsiaConstants.SbjIdUrn, sbjId));

            var uri = new Uri(Options.UserInformationEndpoint + "/" + sbjId);
            var userInfo = await GetUserInformation(uri, tokens);

            if (Options.FetchContactInfo)
            {
                uri = new Uri(Options.UserInformationEndpoint + "/" + sbjId + "/" + EsiaConstants.ContactsUrl);
                var userContacts = await GetUserInformation(uri, tokens);
                userInfo["elements"] = userContacts["elements"];
            }

            var context = new OAuthCreatingTicketContext(
                new ClaimsPrincipal(identity), properties, Context,
                Scheme, Options, Backchannel, tokens, userInfo.ToJsonElement());
            
            context.RunClaimActions();

            await Events.CreatingTicket(context);
            return new AuthenticationTicket(context.Principal, context.Properties, Scheme.Name);
        }

        private async Task<Dictionary<string, object>> GetUserInformation(Uri uri, OAuthTokenResponse tokens)
        {
            var request = new HttpRequestMessage(HttpMethod.Get, uri.AbsoluteUri);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", tokens.AccessToken);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            var response = await Backchannel.SendAsync(request, Context.RequestAborted);
            if (!response.IsSuccessStatusCode)
            {
                throw new HttpRequestException($"An error occurred when retrieving Esia user information ({response.StatusCode}). Please check if the authentication information is correct.");
            }

            var content = await response.Content.ReadAsStringAsync();

            return JsonSerializer.Deserialize<Dictionary<string, object>>(content);
        }

        private static string GetSubjectId(OAuthTokenResponse tokens)
        {
            var payloadString = tokens.AccessToken.Split('.')[1];
            payloadString = Encoding.UTF8.GetString(Base64UrlTextEncoder.Decode(payloadString));
            var payload = JsonDocument.Parse(payloadString);
            return payload.RootElement.GetString(EsiaConstants.SbjIdUrn);
        }
    }
}
