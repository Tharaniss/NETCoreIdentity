using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace NETCoreIdentity.Models
{
    public class ApplicationRole: IdentityRole<string>
    {
        public ApplicationRole(string name)
        {
            base.Name = name;
            base.Id = Guid.NewGuid().ToString();
        }
    }
}
