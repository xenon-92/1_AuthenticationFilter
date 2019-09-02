using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http;
using System.Web.Http.Filters;

namespace _1_AuthenticationFilter
{
    public class IdentityBasicAuthenticationAttribute : Attribute, IAuthenticationFilter
    {
        public bool AllowMultiple { get { return false; } }

        public async Task AuthenticateAsync(HttpAuthenticationContext context, CancellationToken cancellationToken)
        {
            HttpRequestMessage request = context.Request;
            var header = request.Headers.Authorization;
            //if no credentials is present do nothing
            if (header == null)
            {
                return;
            }
            if (!header.Scheme.Equals("Basic", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }
            if (header.Parameter== "Og==" ||string.IsNullOrEmpty(header.Parameter))
            {
                context.ErrorResult = new AuthenticationFailureResult("Missing Credentails", request);
                return;
            }
            //extract username and password
            ExtractUserNameAndPassword extract = new ExtractUserNameAndPassword(header.Parameter);
            string credentials = extract.ConvertFromBase64();
            if (credentials == null)
            {
                context.ErrorResult = new AuthenticationFailureResult("Invalid credentials", request);
                return;
            }
            if (credentials != null)
            {
                string username = credentials.Split(':')[0];
                string password = credentials.Split(':')[1];
                //hit db and check for the credentials
                if (username != null && password != null)
                {
                    context.Principal = await GetClaims(username,password,cancellationToken);
                }
                else
                {
                    context.ErrorResult = new AuthenticationFailureResult("Invalid username or password",request);
                    return;
                }

            }
            else
            {
                context.ErrorResult = new AuthenticationFailureResult("Unable to proceed request",request);
                return;
            }

            //row new NotImplementedException();

        }
        public Task ChallengeAsync(HttpAuthenticationChallengeContext context, CancellationToken cancellationToken)
        {
            var headerValue = new AuthenticationHeaderValue("Basic");
            context.Result = new AddChallengeOnUnauthorised(headerValue, context.Result);
            return Task.FromResult(0);
        }
        public Task<ClaimsPrincipal> GetClaims(string username, string password, CancellationToken cancellationToken)
        {
            List<Claim> claims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name,username),
                new Claim("Password",password),
                new Claim(ClaimTypes.Email,username+"_92@gmail.com"),
                new Claim(ClaimTypes.StreetAddress,username+" Address"),
            };
            ClaimsIdentity id = new ClaimsIdentity(claims, "Basic");
            ClaimsPrincipal principal = new ClaimsPrincipal(new[] { id });
            return Task.FromResult(principal);
        }
    }
    class AddChallengeOnUnauthorised : IHttpActionResult
    {
        public AuthenticationHeaderValue Challenge { get; set; }
        public IHttpActionResult InnerResult { get; set; }

        public AddChallengeOnUnauthorised(AuthenticationHeaderValue challenge,IHttpActionResult innerResult)
        {
            this.Challenge = challenge;
            this.InnerResult = innerResult;
        }
        public async Task<HttpResponseMessage> ExecuteAsync(CancellationToken cancellationToken)
        {
            HttpResponseMessage httpResponse = await InnerResult.ExecuteAsync(cancellationToken);
            if (httpResponse.StatusCode==System.Net.HttpStatusCode.Unauthorized)
            {
                httpResponse.Headers.WwwAuthenticate.Add(Challenge);
            }
            return httpResponse;
        }
    }
    class AuthenticationFailureResult : IHttpActionResult
    {
        public string ReasonPhrase { get; private set; }
        public HttpRequestMessage Request { get; private set; }
        public AuthenticationFailureResult(string reasonPhrase, HttpRequestMessage request)
        {
            this.ReasonPhrase = reasonPhrase;
            this.Request = request;
        }

        public HttpResponseMessage Execute()
        {
            HttpResponseMessage responseMessage = new HttpResponseMessage(System.Net.HttpStatusCode.Unauthorized)
            {
                RequestMessage = Request,
                ReasonPhrase = ReasonPhrase
            };
            return responseMessage;
        }
        public Task<HttpResponseMessage> ExecuteAsync(CancellationToken cancellationToken)
        {
            return Task.FromResult(Execute());
        }

    }
    class ExtractUserNameAndPassword
    {
        public string HeaderParam { get; private set; }
        public ExtractUserNameAndPassword(string str)
        {
            this.HeaderParam = str;
        }
        public string ConvertFromBase64()
        {
            byte[] creds = Convert.FromBase64String(HeaderParam);
            string decoded = Encoding.UTF8.GetString(creds);
            return decoded;
        }
    }
}