using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.Extensions.Configuration;
using System.Threading;
using System.Collections.Generic;

namespace OAuthClaims
{
    public static class Function1
    {
      
     [FunctionName("Function1")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", "post", Route = null)] HttpRequest req,
            ILogger log, Microsoft.Azure.WebJobs.ExecutionContext context)
        {
            log.LogInformation("C# HTTP trigger function processed a request.");


            //read the values from the config settings file
            var config = new ConfigurationBuilder()
                .SetBasePath(context.FunctionAppDirectory)
                .AddJsonFile("local.settings.json", optional: true, reloadOnChange: true) 
                .AddEnvironmentVariables()
                .Build();

            var tokenServerEndpoint = config["OAuth_ServerEndpoint"];
            var issuer = config["OAuth_Issuer"];
            var audiences = config["OAuth_Audiences"];



            var keys = await GetSecurityKeysAsync(tokenServerEndpoint);
           
            TokenValidationParameters validationParameters = new TokenValidationParameters
            {
                ValidIssuer = issuer,
                ValidAudiences = new[] { audiences },
                IssuerSigningKeys = keys 
            };


            //get the bearer token
            var headers = req.Headers;
            var token = string.Empty;
            if(headers.TryGetValue("Authorization", out var authHeader))
            {
                if (authHeader[0].StartsWith("Bearer "))
                {
                     token = authHeader[0].Substring(7, authHeader[0].Length-7);
                }
                else
                {
                    return new UnauthorizedResult();
                }

            }

            //Grab the claims from the token.
            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            SecurityToken validatedToken;
            ClaimsPrincipal principal;
            try
            {
                principal = handler.ValidateToken(token, validationParameters, out  validatedToken);
            }
            catch(SecurityTokenExpiredException ex)
            {
                log.LogError(ex.Message);
                req.HttpContext.Response.Headers.Add("X-Error-Message", $"Token expired at {ex.Expires}");
                return new UnauthorizedResult();
            }
            catch(Exception ex)
            {
                log.LogError(ex.Message);
                return new UnauthorizedResult();
            }


            var sb = new StringBuilder();
            //check if calims has a specific role
            if (principal.IsInRole("crm.read"))
            {
                //execute the business logic for this role.
                sb.AppendLine("crm.read role found in claims using the method principal.IsInRole(\"crm.read\")");
            }
            

            //iterate through the claims to output latter.
            foreach (var claim in principal.Claims)
            {
                var msg = $"CLAIM TYPE: {claim.Type}; CLAIM VALUE: {claim.Value}";
                log.LogInformation(msg);
                sb.AppendLine(msg);
            }


            string name = req.Query["name"];

            string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            dynamic data = JsonConvert.DeserializeObject(requestBody);
            name = name ?? data?.name;
            sb.AppendLine($"Hello, {name}");


            return name != null
                ? (ActionResult)new OkObjectResult(sb.ToString())
                : new BadRequestObjectResult("Please pass a name on the query string or in the request body");
        }


      
        // Get the public keys from the jwks endpoint      
        private static async Task<ICollection<SecurityKey>> GetSecurityKeysAsync(string idpEndpoint )
        {
            var openIdConfigurationEndpoint = $"{idpEndpoint}.well-known/openid-configuration";
            var configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(openIdConfigurationEndpoint, new OpenIdConnectConfigurationRetriever());
            var openIdConfig = await configurationManager.GetConfigurationAsync(CancellationToken.None);
            return openIdConfig.SigningKeys;
        }

    }


   
}
