using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

namespace AN.Authentication.Basic
{
    public interface IAsyncClaimsService
    {
        Task<Claim[]> GetClaimsAsync(string userId, string password, CancellationToken cancellationToken = default);
    }
}
