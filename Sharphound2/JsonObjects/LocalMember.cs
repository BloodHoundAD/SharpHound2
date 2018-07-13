using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Sharphound2.JsonObjects
{
    internal class LocalMember
    {
        private string _type;

        public string Name { get; set; }
        public string Type
        {
            get => _type;
            set => _type = value.ToTitleCase();
        }
    }
}
