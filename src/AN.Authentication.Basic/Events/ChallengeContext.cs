using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace AN.Authentication.Basic.Events
{
    public class ChallengeContext : ResultContext<BasicOptions>
    {
        public ChallengeContext(HttpContext context, AuthenticationScheme scheme, BasicOptions options)
            : base(context, scheme, options) { }

        /// <summary>If true, will skip any default logic for this challenge.</summary>
        public bool Handled { get; set; }
    }
}
