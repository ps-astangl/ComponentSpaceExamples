using ComponentSpace.Saml2.Configuration;
using ComponentSpace.Saml2.Configuration.Resolver;
using ComponentSpace.Saml2.Exceptions;
using ExampleServiceProvider.Data;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Shared;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace ExampleServiceProvider
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.Configure<CookiePolicyOptions>(options =>
            {
                // This lambda determines whether user consent for non-essential cookies is needed for a given request.
                options.CheckConsentNeeded = context => true;

                // SameSiteMode.None is required to support SAML SSO.
                options.MinimumSameSitePolicy = SameSiteMode.None;

                // Some older browsers don't support SameSiteMode.None.
                options.OnAppendCookie = cookieContext => SameSite.CheckSameSite(cookieContext.Context, cookieContext.CookieOptions);
                options.OnDeleteCookie = cookieContext => SameSite.CheckSameSite(cookieContext.Context, cookieContext.CookieOptions);
            });

            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(
                    Configuration.GetConnectionString("DefaultConnection")));

            services.AddIdentity<IdentityUser, IdentityRole>()
                .AddDefaultUI()
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();

            // Optionally add support for JWT bearer tokens.
            // This is required only if JWT bearer tokens are used to authorize access to a web API.
            // It's not required for SAML SSO.
            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options =>
                {
                    options.TokenValidationParameters = new TokenValidationParameters()
                    {
                        ValidateIssuer = true,
                        ValidateAudience = true,
                        ValidateLifetime = true,
                        ValidateIssuerSigningKey = true,
                        ValidIssuer = Configuration["JWT:Issuer"],
                        ValidAudience = Configuration["JWT:Issuer"],
                        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration["JWT:Key"]))
                    };
                });

            // Optionally add cross-origin request sharing services.
            // This is only required for the web API.
            // It's not required for SAML SSO.
            services.AddCors();

            services.AddMvc().SetCompatibilityVersion(CompatibilityVersion.Version_2_1);

            services.ConfigureApplicationCookie(options =>
            {
                // Use a unique identity cookie name rather than sharing the cookie across applications in the domain.
                options.Cookie.Name = "ExampleServiceProvider.Identity";

                // SameSiteMode.None is required to support SAML logout.
                options.Cookie.SameSite = SameSiteMode.None;
            });

            // Add SAML SSO services.
            services.AddSaml(Configuration.GetSection("SAML"));
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseDatabaseErrorPage();
            }
            else
            {
                app.UseExceptionHandler("/Error");
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();
            app.UseCookiePolicy();

            app.UseAuthentication();

            app.UseCors(builder => builder
                .AllowAnyOrigin()
                .AllowAnyMethod()
                .AllowAnyHeader()
                .AllowCredentials());

            app.UseMvc();
        }

        // Demonstrates loading SAML configuration programmatically 
        // rather than through appsettings.json or another JSON configuration file.
        // This is useful if configuration is stored in a custom database, for example.
        // The SAML configuration is registered in ConfigureServices by calling:
        // services.AddSaml(config => ConfigureSaml(config));
        private void ConfigureSaml(SamlConfigurations samlConfigurations)
        {
            samlConfigurations.Configurations = new List<SamlConfiguration>()
            {
                new SamlConfiguration()
                {
                    LocalServiceProviderConfiguration = new LocalServiceProviderConfiguration()
                    {
                        Name = "https://ExampleServiceProvider",
                        Description = "Example Service Provider",
                        AssertionConsumerServiceUrl = "https://localhost:44360/SAML/AssertionConsumerService",
                        SingleLogoutServiceUrl = "https://localhost:44360/SAML/SingleLogoutService",
                        ArtifactResolutionServiceUrl = "https://localhost:44360/SAML/ArtifactResolutionService",
                        LocalCertificates = new List<Certificate>()
                        {
                            new Certificate()
                            {
                                FileName = "certificates/sp.pfx",
                                Password = "password"
                            }
                        }
                    },
                    PartnerIdentityProviderConfigurations = new List<PartnerIdentityProviderConfiguration>()
                    {
                        new PartnerIdentityProviderConfiguration()
                        {
                            Name = "https://ExampleIdentityProvider",
                            Description = "Example Identity Provider",
                            SignAuthnRequest = true,
                            SignLogoutRequest = true,
                            SignLogoutResponse = true,
                            WantLogoutRequestSigned = true,
                            WantLogoutResponseSigned = true,
                            SingleSignOnServiceUrl = "https://localhost:44313/SAML/SingleSignOnService",
                            SingleLogoutServiceUrl = "https://localhost:44313/SAML/SingleLogoutService",
                            ArtifactResolutionServiceUrl = "https://localhost:44313/SAML/ArtifactResolutionService",
                            PartnerCertificates = new List<Certificate>()
                            {
                                new Certificate()
                                {
                                    FileName = "certificates/idp.cer"
                                }
                            }
                        }
                    }
                }
            };
        }
    }

    // Demonstrates loading SAML configuration dynamically using a custom configuration resolver.
    // Hard-coded configuration is returned in this example but more typically configuration would be read from a custom database.
    // The configurationName parameter specifies the SAML configuration in a multi-tenancy application but is not used in this example.
    // The custom configuration resolver is registered in ConfigureServices by calling:
    // services.AddSaml();
    // services.AddTransient<ISamlConfigurationResolver, CustomConfigurationResolver>();
    public class CustomConfigurationResolver : AbstractSamlConfigurationResolver
    {
        public override Task<bool> IsLocalServiceProviderAsync(string configurationName)
        {
            return Task.FromResult(true);
        }

        public override Task<LocalServiceProviderConfiguration> GetLocalServiceProviderConfigurationAsync(string configurationName)
        {
            var localServiceProviderConfiguration = new LocalServiceProviderConfiguration()
            {
                Name = "https://ExampleServiceProvider",
                Description = "Example Service Provider",
                AssertionConsumerServiceUrl = "https://localhost:44360/SAML/AssertionConsumerService",
                SingleLogoutServiceUrl = "https://localhost:44360/SAML/SingleLogoutService",
                ArtifactResolutionServiceUrl = "https://localhost:44360/SAML/ArtifactResolutionService",
                LocalCertificates = new List<Certificate>()
                {
                    new Certificate()
                    {
                        FileName = "certificates/sp.pfx",
                        Password = "password"
                    }
                }
            };

            return Task.FromResult(localServiceProviderConfiguration);
        }

        public override Task<PartnerIdentityProviderConfiguration> GetPartnerIdentityProviderConfigurationAsync(string configurationName, string partnerName)
        {
            if (partnerName != "https://ExampleIdentityProvider")
            {
                throw new SamlConfigurationException($"The partner identity provider {partnerName} is not configured.");
            }

            var partnerIdentityProviderConfiguration = new PartnerIdentityProviderConfiguration()
            {
                Name = "https://ExampleIdentityProvider",
                Description = "Example Identity Provider",
                SignAuthnRequest = true,
                SignLogoutRequest = true,
                SignLogoutResponse = true,
                WantLogoutRequestSigned = true,
                WantLogoutResponseSigned = true,
                SingleSignOnServiceUrl = "https://localhost:44313/SAML/SingleSignOnService",
                SingleLogoutServiceUrl = "https://localhost:44313/SAML/SingleLogoutService",
                ArtifactResolutionServiceUrl = "https://localhost:44313/SAML/ArtifactResolutionService",
                PartnerCertificates = new List<Certificate>()
                {
                    new Certificate()
                    {
                        FileName = "certificates/idp.cer"
                    }
                }
            };

            return Task.FromResult(partnerIdentityProviderConfiguration);
        }

        public override Task<IList<string>> GetPartnerIdentityProviderNamesAsync(string configurationName)
        {
            IList<string> partnerIdentityProviderNames = new List<string> { "https://ExampleIdentityProvider" };

            return Task.FromResult(partnerIdentityProviderNames);
        }
    }
}
