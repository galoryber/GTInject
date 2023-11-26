using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace GTInject.Injection
{
    internal class threadexec
    {
        public static IntPtr SelectThreadOption(IntPtr memaddr, int execoption, int pid, int tid)
        {
            switch (execoption)
            {
                case 1:
                    return execopt1(memaddr, pid, tid);
                    break;
                case 2:
                    return IntPtr.Zero;
                    break;
            }
            return IntPtr.Zero;
        }

        private static IntPtr execopt1(IntPtr memaddr, int ProcID, int ThreadID)
        {
            return IntPtr.Zero;
        }

    }
}
