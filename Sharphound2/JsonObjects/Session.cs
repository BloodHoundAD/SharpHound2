using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Sharphound2.JsonObjects
{
    internal class Session : JsonBase
    {
        private string _userName;
        private string _computerName;

        public string UserName
        {
            get => _userName;
            set => _userName = value.ToUpper();
        }

        public string ComputerName
        {
            get => _computerName;
            set => _computerName = value.ToUpper();
        }

        public int Weight { get; set; }
    }
}
