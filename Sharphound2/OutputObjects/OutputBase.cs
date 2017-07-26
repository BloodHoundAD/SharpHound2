using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Sharphound2.OutputObjects
{
    internal abstract class OutputBase
    {
        public abstract string ToCsv();
        public abstract object ToParam();
    }
}
