using System.Security.Claims;

namespace AN.Authentication.Basic
{
    public interface IClaimsService
    {
        Claim[] GetClaims(string userId, string password);
    }
}
