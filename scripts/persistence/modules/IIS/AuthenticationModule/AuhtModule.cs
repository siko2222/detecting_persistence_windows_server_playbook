using System;
using System.Diagnostics;
using System.Web;
using System.IO;

namespace AuthenticationModule
{
    public class AuthModule: IHttpModule
    {
        public void Init(HttpApplication app)
        {
            app.BeginRequest += new EventHandler(handle_BeginRequest);
        }

        public void handle_BeginRequest(object o, EventArgs e)
        {
            HttpContext context = HttpContext.Current;

            string path = @"C:\Temp\authHandlerModule.log";
            string content = "Hello from the interwebz";

            try
            {
                // Append text to the file
                File.AppendAllText(path, content + Environment.NewLine);
                EventLog.WriteEntry("Application", "File write successful", EventLogEntryType.Information);
            }
            catch (Exception ex)
            {
                // Log the exception to the Event Viewer
                EventLog.WriteEntry("Application", $"Error writing to file: {ex.Message}", EventLogEntryType.Error);
            }
        }

        public void Dispose() { }
    }
}
