using ComponentSpace.Saml2.Configuration.Database;
using ComponentSpace.Saml2.Configuration.Resolver;
using DatabaseIdentityProvider.Data;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Shared;
using System;

namespace DatabaseIdentityProvider
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
            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(
                    Configuration.GetConnectionString("DefaultConnection")));
            services.AddDatabaseDeveloperPageExceptionFilter();
            services.AddDefaultIdentity<IdentityUser>(options => options.SignIn.RequireConfirmedAccount = false)
                .AddEntityFrameworkStores<ApplicationDbContext>();
            
            services.AddRazorPages();

            services.Configure<CookiePolicyOptions>(options =>
            {
                // SameSiteMode.None is required to support SAML SSO.
                options.MinimumSameSitePolicy = SameSiteMode.None;

                // Some older browsers don't support SameSiteMode.None.
                options.OnAppendCookie = cookieContext => SameSite.CheckSameSite(cookieContext.Context, cookieContext.CookieOptions);
                options.OnDeleteCookie = cookieContext => SameSite.CheckSameSite(cookieContext.Context, cookieContext.CookieOptions);
            });

            services.ConfigureApplicationCookie(options =>
            {
                // Use a unique identity cookie name rather than sharing the cookie across applications in the domain.
                options.Cookie.Name = "DatabaseIdentityProvider.Identity";

                // SameSiteMode.None is required to support SAML logout.
                options.Cookie.SameSite = SameSiteMode.None;
            });

            // Add the SAML configuration database context.
            services.AddDbContext<SamlConfigurationContext>(options =>
                options.UseSqlite(Configuration.GetConnectionString("SamlConfigurationConnection"),
                    builder => builder.MigrationsAssembly("DatabaseIdentityProvider")));


            // Add SAML SSO services.
            services.AddSaml();

            var cacheSamlConfiguration = Configuration.GetValue<bool>("CacheSamlConfiguration");

            if (cacheSamlConfiguration)
            {
                // Use the cached resolver backed by the database configuration resolver.
                services.AddTransient<ISamlConfigurationResolver, SamlCachedConfigurationResolver>();

                services.AddTransient<SamlDatabaseConfigurationResolver>();

                services.Configure<SamlCachedConfigurationResolverOptions>(options =>
                {
                    options.CacheSamlConfigurationResolver<SamlDatabaseConfigurationResolver>();
                    options.MemoryCacheEntryOptions = (key, value, memoryCacheEntryOptions) =>
                    {
                        memoryCacheEntryOptions.AbsoluteExpirationRelativeToNow = Configuration.GetValue<TimeSpan?>("SamlCacheExpiration");
                    };
                });
            }
            else
            {
                // Use the database configuration resolver.
                services.AddTransient<ISamlConfigurationResolver, SamlDatabaseConfigurationResolver>();
            }
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseMigrationsEndPoint();
            }
            else
            {
                app.UseExceptionHandler("/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseCookiePolicy();
            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapRazorPages();
                endpoints.MapControllers();
            });
        }
    }
}
