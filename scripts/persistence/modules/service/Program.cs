using System;
using System.ServiceProcess;
using System.IO;
using System.Threading;

namespace ApplicationSupportService
{
    public class ApplicationSupportService : ServiceBase
    {
        private Thread? serviceThread;
        private bool running = true;

        public static void Main()
        {
            ServiceBase.Run(new ApplicationSupportService());
        }

        public ApplicationSupportService()
        {
            this.ServiceName = "ApplicationSupportService";
        }

        protected override void OnStart(string[] args)
        {
            serviceThread = new Thread(new ThreadStart(ServiceWorker));
            serviceThread.Start();
        }

        protected override void OnStop()
        {
            running = false;
            serviceThread?.Join(); // Wait for the thread to finish
        }

        private void ServiceWorker()
        {
            while (running)
            {
                try
                {
                    File.AppendAllText(@"C:\Program Files\Application Support\AppSupportService\logs\log.txt", $"This service is working as intended\n");
                    Thread.Sleep(10000); // Sleep for 5 seconds before writing again
                }
                catch (Exception ex)
                {
                    File.AppendAllText(@"C:\Program Files\Application Support\AppSupportService\logs\internalerrorlog.txt", $"Exception: {ex.Message}\n");
                }
            }
        }
    }
}