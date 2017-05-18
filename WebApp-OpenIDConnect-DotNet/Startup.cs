using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System.Diagnostics;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using System.Collections;
using Microsoft.AspNetCore.Authorization;

namespace WebApp_OpenIDConnect_DotNet
{
    public class Startup
    {
        public Startup(IHostingEnvironment env)
        {
            // Set up configuration sources.
            Configuration = new ConfigurationBuilder()
                .SetBasePath(env.ContentRootPath)
                .AddJsonFile("config.json")
                .AddJsonFile("appsettings.json")
                .Build();
        }

        public IConfigurationRoot Configuration { get; set; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            // Add MVC services to the services container.
            services.AddMvc();

            // Add Authentication services.
            services.AddAuthentication(sharedOptions => sharedOptions.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme);

            services.AddAuthorization(options =>
            {
                //foreach (var accessPolicy in new ArrayList { "policy1", "policy2" })
                //{
                //    options.AddPolicy(accessPolicy, policy => policy.Requirements.Add(new CustomRoleRequirement("myCustomRole")));
                //}

                options.AddPolicy("policy1", policy => policy.Requirements.Add(new CustomRoleRequirement("myCustomRole")));
            });

            services.AddSingleton<IAuthorizationHandler, CustomRoleHandler>();
            //services.AddAuthorization(options =>
            //{
            //    options.AddPolicy("Over21",
            //                      policy => policy.Requirements.Add(new MinimumAgeRequirement(21)));
            //});
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
        {
            // Add the console logger.
            loggerFactory.AddConsole(Configuration.GetSection("Logging"));

            // Configure error handling middleware.
            app.UseExceptionHandler("/Home/Error");

            // Add static files to the request pipeline.
            app.UseStaticFiles();

            // Configure the OWIN pipeline to use cookie auth.
            app.UseCookieAuthentication(new CookieAuthenticationOptions());

            // Configure the OWIN pipeline to use OpenID Connect auth.
            app.UseOpenIdConnectAuthentication(new OpenIdConnectOptions
            {
                //ClientId = Configuration["AzureAD:ClientId"],
                //Authority = String.Format(Configuration["AzureAd:AadInstance"], Configuration["AzureAd:Tenant"]),
                //ResponseType = OpenIdConnectResponseType.CodeIdToken,
                //GetClaimsFromUserInfoEndpoint=true,
                //ClientSecret = Configuration["AzureAd:ClientSecret"],
                //PostLogoutRedirectUri = Configuration["AzureAd:PostLogoutRedirectUri"],
                //Events = new OpenIdConnectEvents
                //{
                //    OnRemoteFailure = OnAuthenticationFailed,
                //    OnTokenValidated = context => {
                //        //
                //        Debug.WriteLine(context.Ticket.Principal.Claims.First(c=>c.Type==ClaimTypes.Upn));
                //        return Task.FromResult(0); }
                //},
            

                AutomaticAuthenticate = true,
                AutomaticChallenge = true,
                ClientId = Configuration["AzureAD:ClientId"],
                Authority = String.Format(Configuration["AzureAd:AadInstance"], Configuration["AzureAd:Tenant"]),
                ClientSecret = Configuration["AzureAd:ClientSecret"],
                CallbackPath = new PathString("/signin-oidc"),
                ResponseType = OpenIdConnectResponseType.CodeIdToken,
                GetClaimsFromUserInfoEndpoint = true,
                Events = new OpenIdConnectEvents
                {
                    OnAuthenticationFailed = OnAuthenticationFailed,
                    OnAuthorizationCodeReceived = OnAuthorizationCodeReceived,
                    OnMessageReceived = OnMessageReceived,
                    OnTicketReceived = OnTicketRecieved,
                    OnTokenValidated = OnTokenValidated,
                    OnUserInformationReceived = OnUserInformationReceived,
                    OnTokenResponseReceived = OnTokenResponseRecieved,
                    OnRemoteFailure = OnRemoteFailure
                }

            });

            // Configure MVC routes
            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });
        }

        // Handle sign-in errors differently than generic errors.
        //private Task OnAuthenticationFailed(FailureContext context)
        //{
        //    context.HandleResponse();
        //    context.Response.Redirect("/Home/Error?message=" + context.Failure.Message);
        //    return Task.FromResult(0);
        //}

        private Task OnRemoteFailure(FailureContext context)
        {
            context.HandleResponse();
            context.Response.Redirect("/Home/Error?message=" + context.Failure.Message);
            return Task.FromResult(0);
        }

        private Task OnAuthenticationFailed(AuthenticationFailedContext context)
        {
            return Task.FromResult(0);
        }

        private Task OnAuthorizationCodeReceived(AuthorizationCodeReceivedContext context)
        {
            //context.Ticket.Principal.Claims.ad
            return Task.FromResult(0);
        }

        private Task OnMessageReceived(MessageReceivedContext context)
        {
            return Task.FromResult(0);
        }

        private Task OnTicketRecieved(TicketReceivedContext context)
        {
            return Task.FromResult(0);
        }

        private Task OnTokenValidated(TokenValidatedContext context)
        {
           ((ClaimsIdentity)context.Ticket.Principal.Identity).AddClaim(new Claim("myClaim", "myClaimValue"));
            return Task.FromResult(0);
        }
        private Task OnUserInformationReceived(UserInformationReceivedContext context)
        {
            return Task.FromResult(0);
        }

        private Task OnTokenResponseRecieved(TokenResponseReceivedContext context)
        {
            return Task.FromResult(0);
        }

    }
    public class ClaimsTransformer : IClaimsTransformer
    {
        //Task<ClaimsPrincipal> TransformAsync(ClaimsTransformationContext context);

        public Task<ClaimsPrincipal> TransformAsync(ClaimsTransformationContext context)
        {
            ((ClaimsIdentity)context.Principal.Identity).AddClaim(new Claim("myClaim", "myClaimValue"));
            //((ClaimsIdentity)principal.Identity).AddClaim(new Claim("ProjectReader", "true"));
            return Task.FromResult(context.Principal);
        }
    }

    public class MinimumAgeRequirement : IAuthorizationRequirement
    {
        public MinimumAgeRequirement(int age)
        {
            MinimumAge = age;
        }

        protected int MinimumAge { get; set; }
    }

    class CustomRoleRequirement : IAuthorizationRequirement
    {
        public CustomRoleRequirement(string roleName)
        {
            RoleName = roleName;
        }

        public String RoleName{ get; set; }
    }

    class CustomRoleHandler : AuthorizationHandler<CustomRoleRequirement>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, CustomRoleRequirement requirement)
        {
            //if (context.User.HasClaim(claim => { return claim.Subject.Name == "roles"; }))
            //{
            //    var roles = context.User.FindFirst(claim => { return claim.Subject.Name == "roles"; });

            //    if (roles.Value.Split(new char[] { ',', ';' }).Contains(requirement.RoleName))
            //        context.Succeed(requirement);
            //}
            context.Succeed(requirement);
            return Task.CompletedTask;
           
        }
    }
}
