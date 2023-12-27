using System.Threading.Tasks;
using System;

namespace AN.Authentication.Basic.Events
{
    /// <summary>
    /// Specifies events which the basic authentication handler invokes to enable developer control over the authentication process.
    /// </summary>
    public class BasicEvents
    {
        /// <summary>Invoked when a protocol message is first received.</summary>
        public Func<MessageReceivedContext, Task> OnMessageReceived { get; set; } = context => Task.CompletedTask;

        /// <summary>Invoked if authentication fails during request processing. The exceptions will be re-thrown after this event unless suppressed.</summary>
        public Func<FailedContext, Task> OnFailed { get; set; } = context => Task.CompletedTask;

        /// <summary>Invoked before a challenge is sent back to the caller.</summary>
        public Func<ChallengeContext, Task> OnChallenge { get; set; } = context => Task.CompletedTask;

        /// <summary>Invoked if authorization fails and results in a Forbidden response.</summary>
        public Func<ForbiddenContext, Task> OnForbidden { get; set; } = context => Task.CompletedTask;

        /// <summary>Invoked after request principal instance created.</summary>
        public Func<PrincipalCreatedContext, Task> OnPrincipalCreated { get; set; } = context => Task.CompletedTask;

        /// <summary>Invoked when a protocol message is first received.</summary>
        /// <param name="context">The <see cref="MessageReceivedContext"/>.</param>
        public virtual Task MessageReceivedAsync(MessageReceivedContext context) => OnMessageReceived(context);

        /// <summary>Invoked if exceptions are thrown during request processing. The exceptions will be re-thrown after this event unless suppressed.</summary>
        /// <param name="context">The <see cref="FailedContext"/>.</param>
        public virtual Task Failed(FailedContext context) => OnFailed(context);

        /// <summary>Invoked if authorization fails and results in a Forbidden response</summary>
        /// <param name="context">The <see cref="ForbiddenContext"/>.</param>
        public virtual Task Forbidden(ForbiddenContext context) => OnForbidden(context);

        /// <summary>Invoked before a challenge is sent back to the caller.</summary>
        /// <param name="context">The <see cref="ChallengeContext"/>.</param>
        public virtual Task Challenge(ChallengeContext context) => OnChallenge(context);

        /// <summary>Invoked after request principal instance created.</summary>
        /// <param name="context">The <see cref="PrincipalCreatedContext"/>.</param>
        public virtual Task PrincipalCreatedAsync(PrincipalCreatedContext context) => OnPrincipalCreated(context);
    }
}
