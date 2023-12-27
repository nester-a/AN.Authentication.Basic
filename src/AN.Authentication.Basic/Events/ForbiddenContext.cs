using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace AN.Authentication.Basic.Events
{
    public class ForbiddenContext : ResultContext<BasicOptions>
    {
        public ForbiddenContext(HttpContext context, AuthenticationScheme scheme, BasicOptions options)
            : base(context, scheme, options) { }

        /// <summary>If true, will skip any default logic for this challenge.</summary>
        public bool Handled { get; set; }
    }
}
