using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Primitives;

namespace NETCoreIdentity.DTO
{
    public class RoleClaimDTO
    {
        [Required]
        [Display(Name = "Name")]
        public string Name { get; set; }
    }

    public class ClaimStore
    {
        public List<Claim> GetClaims(string Name)
        {
            switch(Name)
            {
                case "Admin" : return new List<Claim>()
                    {
                        new Claim("Account", "Create"),
                        new Claim("Account", "Update"),
                        new Claim("Account", "Read"),
                        new Claim("Account", "Delete"),
                    };
                default:                    
                    break;
            }
            return new List<Claim>();
        }
    }
}   
