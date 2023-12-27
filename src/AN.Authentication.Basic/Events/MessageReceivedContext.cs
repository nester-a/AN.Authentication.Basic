using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace AN.Authentication.Basic.Events
{
    public class MessageReceivedContext : ResultContext<BasicOptions>
    {
        public MessageReceivedContext(HttpContext context, AuthenticationScheme scheme, BasicOptions options)
            : base(context, scheme, options) { }

        public string UserId { get; set; }
        public string Password { get; set; }
    }
}
