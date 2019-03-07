using System.Collections.Concurrent;
using System.IO;
using ProtoBuf;
using Sharphound2.Enumeration;

namespace Sharphound2
{
    internal class Cache
    {
        private ConcurrentDictionary<string, string> _userCache;
        private ConcurrentDictionary<string, string> _groupCache;
        private ConcurrentDictionary<string, string> _computerCache;
        private ConcurrentDictionary<string, string> _domainToSidCache;
        private ConcurrentDictionary<string, string[]> _globalCatalogMap;

        private readonly string _fileName;

        public static Cache Instance { get; private set; }

        private readonly Sharphound.Options _options;

        public static void CreateInstance(Sharphound.Options opts)
        {
            Instance = new Cache(opts);
        }

        private Cache(Sharphound.Options opts)
        {
            _options = opts;
            _fileName = Path.Combine(_options.JsonFolder, _options.CacheFile);
            var oldFilePath = Path.Combine(_options.JsonFolder, "BloodHound.bin");
            if (File.Exists(oldFilePath))
            {
                File.Move(oldFilePath, _fileName);
            }
            
            LoadCache();
        }

        private void LoadCache()
        {
            if (File.Exists(_fileName) && !_options.Invalidate)
            {
                using (var file = File.OpenRead(_fileName))
                {
                    _userCache =
                        Serializer.DeserializeWithLengthPrefix<ConcurrentDictionary<string, string>>(file,
                            PrefixStyle.Base128);
                    _groupCache = Serializer.DeserializeWithLengthPrefix<ConcurrentDictionary<string, string>>(file,
                        PrefixStyle.Base128);
                    _computerCache = Serializer.DeserializeWithLengthPrefix<ConcurrentDictionary<string, string>>(file,
                        PrefixStyle.Base128);
                    _domainToSidCache = Serializer.DeserializeWithLengthPrefix<ConcurrentDictionary<string, string>>(
                        file,
                        PrefixStyle.Base128);
                    _globalCatalogMap = Serializer
                        .DeserializeWithLengthPrefix<ConcurrentDictionary<string, string[]>>(file,
                            PrefixStyle.Base128);
                }
            }
            else
            {
                _userCache = new ConcurrentDictionary<string, string>();
                _groupCache = new ConcurrentDictionary<string, string>();
                _computerCache = new ConcurrentDictionary<string, string>();
                _domainToSidCache = new ConcurrentDictionary<string, string>();
                _globalCatalogMap = new ConcurrentDictionary<string, string[]>();
            }
        }

        public void SaveCache()
        {
            if (_options.NoSaveCache)
                return;

            using (var file = File.Create(_fileName))
            {
                Serializer.SerializeWithLengthPrefix(file,_userCache,PrefixStyle.Base128);
                Serializer.SerializeWithLengthPrefix(file, _groupCache, PrefixStyle.Base128);
                Serializer.SerializeWithLengthPrefix(file, _computerCache, PrefixStyle.Base128);
                Serializer.SerializeWithLengthPrefix(file, _domainToSidCache, PrefixStyle.Base128);
                Serializer.SerializeWithLengthPrefix(file, _globalCatalogMap, PrefixStyle.Base128);
            }
        }

        public bool GetMapValue(string key, string objType, out string resolved)
        {
            switch (objType)
            {
                case "group":
                    return _groupCache.TryGetValue(key, out resolved);
                case "user":
                    return _userCache.TryGetValue(key, out resolved);
                case "computer":
                    return _computerCache.TryGetValue(key, out resolved);
                default:
                    resolved = null;
                    return false;
            }
        }

        public bool GetMapValueUnknownType(string key, out MappedPrincipal principal)
        {
            if (_groupCache.TryGetValue(key, out string resolved))
            {
                principal = new MappedPrincipal(resolved, "group");
                return true;
            }
            if (_userCache.TryGetValue(key, out resolved))
            {
                principal = new MappedPrincipal(resolved, "user");
                return true;
            }
            if (_computerCache.TryGetValue(key, out resolved))
            {
                principal = new MappedPrincipal(resolved, "computer");
                return true;
            }
            principal = null;
            return false;
        }

        public void AddMapValue(string key, string objType, string resolved)
        {
            switch (objType)
            {
                case "group":
                    _groupCache.TryAdd(key, resolved);
                    return;
                case "user":
                    _userCache.TryAdd(key, resolved);
                    return;
                case "computer":
                    _computerCache.TryAdd(key, resolved);
                    return;
                default:
                    return;
            }
        }

        public bool GetDomainFromSid(string sid, out string domainName)
        {
            return _domainToSidCache.TryGetValue(sid, out domainName);
        }

        public void AddDomainFromSid(string sid, string domainName)
        {
            Utils.Debug($"Cached {sid} to {domainName}");
            _domainToSidCache.TryAdd(sid, domainName);
        }

        public bool GetGcMap(string username, out string[] domains)
        {
            return _globalCatalogMap.TryGetValue(username, out domains);
        }

        public void AddGcMap(string username, string[] domains)
        {
            _globalCatalogMap.TryAdd(username, domains);
        }
    }
}
