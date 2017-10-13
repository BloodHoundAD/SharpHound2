namespace Sharphound2.OutputObjects
{
    internal abstract class OutputBase
    {
        public abstract string ToCsv();
        public abstract object ToParam();
        public abstract string TypeHash();
    }
}
