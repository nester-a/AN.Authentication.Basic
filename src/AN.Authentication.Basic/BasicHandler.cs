using AN.Authentication.Basic.Events;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;
using System;
using System.Linq;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace AN.Authentication.Basic
{
    public class BasicHandler : AuthenticationHandler<BasicOptions>
    {
        private readonly IAsyncClaimsService asyncClaimsService;
        private readonly IClaimsService claimsService;

        private new BasicEvents Events => (BasicEvents)base.Events;

        public BasicHandler(IOptionsMonitor<BasicOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock,
            IAsyncClaimsService asyncClaimsService = null,
            IClaimsService claimsService = null)
            : base(options, logger, encoder, clock)
        {
            this.asyncClaimsService = asyncClaimsService;
            this.claimsService = claimsService;
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var cancellation = Request.HttpContext.RequestAborted;
            try
            {
                // Give application opportunity to find from a different location, adjust, or reject credentials token
                var messageReceivedContext = new MessageReceivedContext(Context, Scheme, Options);

                await Events.MessageReceivedAsync(messageReceivedContext);

                if (messageReceivedContext.Result != null)
                {
                    return messageReceivedContext.Result;
                }

                var userId = messageReceivedContext.UserId;
                var password = messageReceivedContext.Password;

                if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(password))
                {
                    var header = Request.Headers[HeaderNames.Authorization].ToString();

                    if (string.IsNullOrWhiteSpace(header) || !header.StartsWith($"{Scheme.Name} "))
                    {
                        return AuthenticateResult.NoResult();
                    }

                    var trimedHeader = header.Substring(Scheme.Name.Length).Trim();

                    string decodedHeader;

                    if (Options.EncodedHeaderAsyncDecoder != null)
                    {
                        decodedHeader = await Options.EncodedHeaderAsyncDecoder(trimedHeader, cancellation);
                    }
                    else
                    {
                        decodedHeader = Options.EncodedHeaderDecoder(trimedHeader);
                    }

                    var dataArr = decodedHeader.Split(Options.CredentialsSeparator);

                    if (dataArr.Length != 2)
                    {
                        return await AuthenticationFailed(Options.IncorrectCredentialsFormatFailureMessage);
                    }

                    userId = dataArr[0];
                    password = dataArr[1];
                }

                Claim[] claims;
                if (asyncClaimsService != null)
                {
                    claims = await asyncClaimsService.GetClaimsAsync(userId, password, cancellation);
                }
                else if (claimsService != null)
                {
                    claims = claimsService.GetClaims(userId, password);
                }
                else if (Options.AsyncClaimsFactory != null)
                {
                    claims = await Options.AsyncClaimsFactory(userId, password, cancellation);
                }
                else
                {
                    claims = Options.ClaimsFactory(userId, password);
                }

                if (!claims.Any())
                {
                    return await AuthenticationFailed(Options.IncorrectCredentialsFailureMessage);
                }

                var claimsIdentity = new ClaimsIdentity(claims, Scheme.Name);

                var principal = new ClaimsPrincipal(claimsIdentity);

                var principalContext = new PrincipalCreatedContext(Context, Scheme, Options, null);
                await Events.PrincipalCreatedAsync(principalContext);

                var ticket = new AuthenticationTicket(principal, Scheme.Name);

                return AuthenticateResult.Success(ticket);
            }
            catch (Exception ex)
            {
                Logger.LogError(3, ex, "Exception occurred while processing authentication.");

                return await AuthenticationFailed(ex.Message, ex);

                throw;
            }
        }

        protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            var chanllengeContext = new ChallengeContext(Context, Scheme, Options);

            await Events.Challenge(chanllengeContext);

            if (chanllengeContext.Handled)
            {
                return;
            }

            Response.Headers.Append(HeaderNames.WWWAuthenticate, Scheme.Name);

            await base.HandleChallengeAsync(properties);
        }

        protected override async Task HandleForbiddenAsync(AuthenticationProperties properties)
        {
            var forbiddenContext = new ForbiddenContext(Context, Scheme, Options);

            await Events.Forbidden(forbiddenContext);

            if (forbiddenContext.Handled)
            {
                return;
            }

            await base.HandleForbiddenAsync(properties);
        }

        private async Task<AuthenticateResult> AuthenticationFailed(string failureMessage, Exception ex = null)
        {
            var failedContext = new FailedContext(Context, Scheme, Options)
            {
                Exception = ex
            };

            await Events.Failed(failedContext);
            if (failedContext.Result != null)
            {
                return failedContext.Result;
            }
            else
            {
                return AuthenticateResult.Fail(failureMessage);
            }
        }
    }
}
