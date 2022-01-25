Older Browser Support of SameSite
=================================

Safari on iOS 12 and macOS 10.15 Mojave doesn't support a SameSite mode of None and treats this as Strict.
This bug is fixed in iOS 13 and macOS Catalina.

As a workaround, the code included in SameSite.cs detects whether the browser correctly supports SameSite=None and, 
if it doesn't, no SameSite mode is included.

The code is based on that at:

https://devblogs.microsoft.com/aspnet/upcoming-samesite-cookie-changes-in-asp-net-and-asp-net-core/

To include this support in your application:

1. Add SameSite.cs to your project.

2. In the application Startup, configure OnAppendCookie and OnDeleteCookie actions to call the CheckSameSite.

For example:

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
