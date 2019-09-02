using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Threading;
using System.Web.Http;


namespace _1_AuthenticationFilter.Controllers
{
    public class DemoController : ApiController
    {
        [IdentityBasicAuthentication]
        [Authorize]
        [HttpGet]
        public HttpResponseMessage CheckDemo()
        {
            ClaimsPrincipal principal = Thread.CurrentPrincipal as ClaimsPrincipal;
            ClaimsIdentity id = principal.Identity as ClaimsIdentity;
            return Request.CreateResponse(HttpStatusCode.OK,id.Claims);
        }
    }
}
