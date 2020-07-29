using System.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace ClientIpChecker.ActionFilters
{
    public class ClientIpCheckActionFilter : ActionFilterAttribute
    {
        private readonly string[] _safeList;
        public ClientIpCheckActionFilter(string[] safeList)
        {
            _safeList = safeList;
        }
        public override void OnActionExecuting(ActionExecutingContext context)
        {
            var remoteIp = context.HttpContext.Connection.RemoteIpAddress;

            var badIp = true;

            if (remoteIp.IsIPv4MappedToIPv6)
            {
                remoteIp = remoteIp.MapToIPv4();
            }

            foreach (var safeIp in _safeList)
            {
                var testIp = IPAddress.Parse(safeIp);

                if (testIp.Equals(remoteIp))
                {
                    badIp = false;
                    break;
                }
            }

            if (badIp)
            {
                context.Result = new StatusCodeResult(StatusCodes.Status403Forbidden);
                return;
            }

            base.OnActionExecuting(context);
        }
    }
}
