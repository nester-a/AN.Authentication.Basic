using Microsoft.AspNetCore.Authentication;
using System;

namespace AN.Authentication.Basic
{
    public static class BasicExtensions
    {
        public static AuthenticationBuilder AddBasic(this AuthenticationBuilder builder)
        {
            return builder.AddBasic(BasicDefaults.AuthenticationScheme);
        }

        public static AuthenticationBuilder AddBasic(this AuthenticationBuilder builder, string authenticationScheme)
        {
            return builder.AddBasic(authenticationScheme, _ => { });
        }

        public static AuthenticationBuilder AddBasic(this AuthenticationBuilder builder, Action<BasicOptions> configure)
        {
            return builder.AddBasic(BasicDefaults.AuthenticationScheme, configure);
        }

        public static AuthenticationBuilder AddBasic(this AuthenticationBuilder builder, string authenticationScheme, Action<BasicOptions> configure)
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            if (authenticationScheme == null)
            {
                throw new ArgumentNullException(nameof(authenticationScheme));
            }

            if (configure == null)
            {
                throw new ArgumentNullException(nameof(configure));
            }

            return builder.AddScheme<BasicOptions, BasicHandler>(authenticationScheme, configure);
        }
    }
}
