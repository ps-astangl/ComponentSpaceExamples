using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace ExampleServiceProvider.Pages
{
    [Authorize]
    public class ClaimsModel : PageModel
    {
        public void OnGet()
        {
        }
    }
}