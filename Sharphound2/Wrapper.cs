namespace Sharphound2
{
    //This class exists because of a memory leak in BlockingCollection. By setting the reference to Item to null after enumerating it,
    //we can force garbage collection of the internal item, while the Wrapper is held by the collection.
    //This is highly preferrable because the internal item consumes a lot of memory while the wrapper barely uses any
    internal class Wrapper<T>
    {
        public T Item { get; set; }
    }
}
