using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using System;

namespace AN.Authentication.Basic.Events
{
    public class FailedContext : ResultContext<BasicOptions>
    {
        public FailedContext(HttpContext context, AuthenticationScheme scheme, BasicOptions options)
            : base(context, scheme, options) { }

        public Exception Exception { get; set; }
    }
}
