#pragma checksum "C:\Users\Alfred.Stangl\Downloads\SAMLv20.Core-evaluation\SAML for .NET Core\Examples\NET-Core-3.1\SSO\ExampleServiceProvider\Pages\Contact.cshtml" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "8e6927ca38d9f5a5dec88de2a650195c746dd9d6"
// <auto-generated/>
#pragma warning disable 1591
[assembly: global::Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemAttribute(typeof(ExampleServiceProvider.Pages.Pages_Contact), @"mvc.1.0.razor-page", @"/Pages/Contact.cshtml")]
namespace ExampleServiceProvider.Pages
{
    #line hidden
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.Rendering;
    using Microsoft.AspNetCore.Mvc.ViewFeatures;
#nullable restore
#line 1 "C:\Users\Alfred.Stangl\Downloads\SAMLv20.Core-evaluation\SAML for .NET Core\Examples\NET-Core-3.1\SSO\ExampleServiceProvider\Pages\_ViewImports.cshtml"
using Microsoft.AspNetCore.Identity;

#line default
#line hidden
#nullable disable
#nullable restore
#line 2 "C:\Users\Alfred.Stangl\Downloads\SAMLv20.Core-evaluation\SAML for .NET Core\Examples\NET-Core-3.1\SSO\ExampleServiceProvider\Pages\_ViewImports.cshtml"
using ExampleServiceProvider;

#line default
#line hidden
#nullable disable
#nullable restore
#line 3 "C:\Users\Alfred.Stangl\Downloads\SAMLv20.Core-evaluation\SAML for .NET Core\Examples\NET-Core-3.1\SSO\ExampleServiceProvider\Pages\_ViewImports.cshtml"
using ExampleServiceProvider.Data;

#line default
#line hidden
#nullable disable
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"8e6927ca38d9f5a5dec88de2a650195c746dd9d6", @"/Pages/Contact.cshtml")]
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"610895f6fcf6a614ff80e7a5307a1eab31243a5e", @"/Pages/_ViewImports.cshtml")]
    public class Pages_Contact : global::Microsoft.AspNetCore.Mvc.RazorPages.Page
    {
        #pragma warning disable 1998
        public async override global::System.Threading.Tasks.Task ExecuteAsync()
        {
#nullable restore
#line 3 "C:\Users\Alfred.Stangl\Downloads\SAMLv20.Core-evaluation\SAML for .NET Core\Examples\NET-Core-3.1\SSO\ExampleServiceProvider\Pages\Contact.cshtml"
  
    ViewData["Title"] = "Contact";

#line default
#line hidden
#nullable disable
            WriteLiteral(@"
<h1>Contact</h1>

<p>If you need assistance, please feel free to contact us by email or on our <a href=""https://www.componentspace.com/forums"" target=""_blank"">online forums</a>.</p>

<address>
    <strong>Support:</strong> <a href=""mailto:support@componentspace.com"">support@componentspace.com</a><br />
    <strong>Sales:</strong> <a href=""mailto:sales@componentspace.com"">sales@componentspace.com</a>
</address>
");
        }
        #pragma warning restore 1998
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.ViewFeatures.IModelExpressionProvider ModelExpressionProvider { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.IUrlHelper Url { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.IViewComponentHelper Component { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.Rendering.IJsonHelper Json { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper<ExampleServiceProvider.Pages.ContactModel> Html { get; private set; }
        public global::Microsoft.AspNetCore.Mvc.ViewFeatures.ViewDataDictionary<ExampleServiceProvider.Pages.ContactModel> ViewData => (global::Microsoft.AspNetCore.Mvc.ViewFeatures.ViewDataDictionary<ExampleServiceProvider.Pages.ContactModel>)PageContext?.ViewData;
        public ExampleServiceProvider.Pages.ContactModel Model => ViewData.Model;
    }
}
#pragma warning restore 1591
