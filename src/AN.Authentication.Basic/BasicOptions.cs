using System.Security.Claims;
using System.Threading.Tasks;
using System.Threading;
using System;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using AN.Authentication.Basic.Events;

namespace AN.Authentication.Basic
{
    public class BasicOptions : AuthenticationSchemeOptions
    {
        public BasicOptions()
        {
            Events = new BasicEvents();
        }

        public Func<string, string, Claim[]> ClaimsFactory { get; set; } = (userId, password) => new Claim[] { new Claim(ClaimTypes.NameIdentifier, userId) };

        public Func<string, string, CancellationToken, Task<Claim[]>> AsyncClaimsFactory { get; set; } = null;

        public Func<string, string> EncodedHeaderDecoder { get; set; } = defaultBase64EncodedString =>
        {
            var bytes = Convert.FromBase64String(defaultBase64EncodedString);
            return Encoding.ASCII.GetString(bytes);
        };

        public Func<string, CancellationToken, Task<string>> EncodedHeaderAsyncDecoder { get; set; } = null;

        public char CredentialsSeparator { get; set; } = ':';

        public string IncorrectCredentialsFailureMessage { get; set; } = "Incorrect credentials.";

        public string IncorrectCredentialsFormatFailureMessage { get; set; } = "Incorrect credentials format.";
    }
}
