# AN.Authentication.Basic

This project contains an implementation of **Basic Authentication Scheme** for ASP.NET Core. See the [RFC-7617](https://www.ietf.org/rfc/rfc7617.txt).

## Add Basic Authentication

To add Basic authentication in .NET Core, we need to modify `Program.cs` file. **If you are using .NET Core version 5 or less, you have to add the modifications in the** `Startup.cs` **file inside the** `ConfigureServices` **method.**

Add the code to configure Basic authentication right above the `builder.Services.AddAuthentication()` line:

```c#
builder.Services.AddAuthentication()
                .AddBasic(BasicDefaults.AuthenticationScheme);
```

## Basic Authentication Configuration

To configure Basic authentication, we need use delegate from overloaded method `AddBasic(string authenticationScheme, Action<BasicOptions> configure)`:

```c#
builder.Services.AddAuthentication()
                .AddBasic(BasicDefaults.AuthenticationScheme, configure => {
                    //some options will be here
                });
```


### User credentials separator
User credentials (user-id and password) constructs by concatenating the user-id, a single colon (':') character, and the password.
If your credentials is separated by another symbol, then it can be configured with the option `CredentialsSeparator`:

```c#
builder.Services.AddAuthentication()
                .AddBasic(BasicDefaults.AuthenticationScheme, configure => {
                    //Default option value is single colon (':')
                    configure.CredentialsSeparator = '~'
                });
```


### Credentials encoding scheme
By default user credentials encoded by `Base64` into a sequence of US-ASCII characters.
If your credentials is by another algorithm or scheme, then it can be configured with the option `EncodedHeaderDecoder`:

```c#
builder.Services.AddAuthentication()
                .AddBasic(BasicDefaults.AuthenticationScheme, configure => {
                    configure.EncodedHeaderDecoder = credentials => DecodeCretentialsToString(credentials);
                });
```
Or you can use `EncodedHeaderAsyncDecoder` for asynchronous decode:
```c#
builder.Services.AddAuthentication()
                .AddBasic(BasicDefaults.AuthenticationScheme, configure => {
                    configure.EncodedHeaderAsyncDecoder = async (credentials, cancellationToken) => await DecodeCretentialsToStringAsync(credentials, cancellationToken);
                });
```
If both the `EncodedHeaderAsyncDecoder` and `EncodedHeaderDecoder` options are implemented, `BasicHandler` will use only `EncodedHeaderAsyncDecoder` to work:
```c#
builder.Services.AddAuthentication()
                .AddBasic(BasicDefaults.AuthenticationScheme, configure => {
                    //This one will be used
                    configure.EncodedHeaderAsyncDecoder = async (credentials, cancellationToken) => await DecodeCretentialsToStringAsync(credentials, cancellationToken);

                    //This one will be ignored
                    configure.EncodedHeaderDecoder = credentials => DecodeCretentialsToString(credentials);
                });
```


### ClaimsPrincipal object creation
After decoding user credentials, it will be split into two separed strings (user-id and password). Then user-id and password will be used to create `Claim[]` by `ClaimsFactory` option for final `ClaimsIdentity`.
By default this `ClaimsFactory` creates `Claim[]` with only one `Claim` with type [NameIdentifier](https://learn.microsoft.com/ru-ru/dotnet/api/system.security.claims.claimtypes.nameidentifier?view=netcore-3.0).
If you need add another claims or get claims from storage, you can overload `ClaimsFactory` option:
```c#
builder.Services.AddAuthentication()
                .AddBasic(BasicDefaults.AuthenticationScheme, configure => {
                    configure.ClaimsFactory = (userId, password) => GetUserClaimsFromStorage(userId, password);
                });
```
Or you can use `AsyncClaimsFactory` for asynchronous `Claim[]` create:
```c#
builder.Services.AddAuthentication()
                .AddBasic(BasicDefaults.AuthenticationScheme, configure => {
                    configure.AsyncClaimsFactory = async (userId, password, cancellationToken) => await GetUserClaimsFromStorageAsync(userId, password, cancellationToken);
                });
```
Same as when you use header decoding option, if both the `AsyncClaimsFactory` and `ClaimsFactory` options are implemented, `BasicHandler` will use only `AsyncClaimsFactory` to work:
```c#
builder.Services.AddAuthentication()
                .AddBasic(BasicDefaults.AuthenticationScheme, configure => {
                    //This one will be used
                    configure.AsyncClaimsFactory = async (userId, password, cancellationToken) => await GetUserClaimsFromStorageAsync(userId, password, cancellationToken);

                    //This one will be ignored
                    configure.ClaimsFactory = (userId, password) => GetUserClaimsFromAnotherStorage(userId, password);
                });
```

### Dependency Injection for ClaimsPrincipal object creation
If you want to get `Claim[]` from a service that works with dependency injection, you need to add service that implement `IClaimsService` or `IAsyncClaimsService` to the `IServiceCollection`.

```c#
builder.Services.AddTransient<IClaimsService, MyClaimsService>();
```

Both interfaces implement methods that returns an `Claim[]`.
```c#

//sync service
public class ClaimsService : IClaimsService
{
    private readonly UserStorage storage;

    public ClaimsService(UserStorage storage)
    {
        this.storage = storage;
    }

    public Claim[] GetClaims(string userId, string password)
        => storage.GetUserClaimsFromStorage(userId, password);
}

//async service
public class AsyncClaimsService : IAsyncClaimsService
{
    private readonly UserStorage storage;

    public AsyncClaimsService(UserStorage storage)
    {
        this.storage = storage;
    }

    public async Task<Claim[]> GetClaimsAsync(string userId, string password, CancellationToken cancellationToken = default)
        => await storage.GetUserClaimsFromStorageAsync(userId, password, cancellationToken);
}
```

In case both types of services are added, only `IAsyncClaimsService` will be used.

If both one of `ClaimService` and one of options `ClaimsFactory` are implemented in same time, only the service will be used to create the `Claim[]`.

## Basic Authentication Events
The following events may occur during Basic authentication, which we can handle:
* `OnMessageReceived` - Invoked when a protocol message is first received.
* `OnFailed` - Invoked if authentication fails during request processing. The exceptions will be re-thrown after this event unless suppressed.
* `OnChallenge` - Invoked before a challenge is sent back to the caller.
* `OnForbidden` - Invoked if authorization fails and results in a Forbidden response.
* `OnPrincipalCreated` - Invoked after request principal instance created. 

All this events is part of `BasicEvents` object.

Events handling is the same as in other authentication schemes:
```c#
builder.Services.AddAuthentication()
                .AddBasic(BasicDefaults.AuthenticationScheme, configure => {
                    configure.Events = new BasicEvents()
                    {
                        OnMessageReceived = context => {
                            //handle this event
                            return Task.CompletedTask;
                        }
                    }
                });
```
