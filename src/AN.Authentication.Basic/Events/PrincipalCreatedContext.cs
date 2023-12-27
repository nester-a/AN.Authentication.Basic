using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace AN.Authentication.Basic.Events
{
    public class PrincipalCreatedContext : PrincipalContext<BasicOptions>
    {
        public PrincipalCreatedContext(HttpContext context, AuthenticationScheme scheme, BasicOptions options, AuthenticationProperties properties)
            : base(context, scheme, options, properties) { }
    }
}
