using System;
using Microsoft.AspNetCore.Identity;

namespace API.Models.Identity
{
    public class UserToken : IdentityUserToken<Guid>
    {
    }
}