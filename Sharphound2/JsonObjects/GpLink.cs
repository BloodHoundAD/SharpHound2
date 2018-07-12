using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Sharphound2.JsonObjects
{
    internal class GpLink
    {
        private string _name;

        public bool? IsEnforced { get; set; }
        public string Name
        {
            get => _name;
            set => _name = value.ToUpper();
        }
    }
}
