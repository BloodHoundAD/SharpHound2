namespace Sharphound2.OutputObjects
{
    internal class Session : OutputBase
    {
        public string UserName { get; set; }
        public string ComputerName { get; set; }
        public int Weight { get; set; }

        public override string ToCsv()
        {
            return $"{UserName.ToUpper()},{ComputerName.ToUpper()},{Weight}";
        }

        public  override object ToParam()
        {
            return new
            {
                account = UserName.ToUpper(),
                computer = ComputerName.ToUpper(),
                weight = Weight
            };
        }
    }
}
