using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using McMaster.Extensions.CommandLineUtils;
using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json;
using Zyborg.Lockbox.Messages;
using Zyborg.Lockbox.Server.Data;
using Zyborg.Lockbox.Server.Data.EF;

namespace Zyborg.Lockbox.Server.CLI
{
    [Subcommand(new[] {
        typeof(ExportStaticFakesCommand),
        typeof(ListUsersCommand),
        typeof(CreateUserCommand),
        typeof(ListSessionsCommand),
        typeof(AuthCommand),
        typeof(ListBoxesCommand),
        typeof(CreateBoxCommand),
        typeof(ListEntriesCommand),
        typeof(CreateEntryCommand),
        typeof(ReadEntryCommand),
    })]
    class Program
    {
        public const string AclTokenCache = ".zlkbx_acl_token";
        public const string StaticFakesSource = "static-fakes.json";
        public static readonly string StaticFakesPath;

        private static readonly byte[] ChallengeMask;
        private static readonly byte[] FakeMasterSalt;
        private static readonly byte[] FakeMasterKey;
        private static readonly byte[] FakeAsymPubKey;
        private static readonly byte[] FakeAsymPrvKey;
        private static readonly byte[] FakeAsymPrvKeyWrapped;

        static Program()
        {
            StaticFakesPath = Path.Combine(Path.GetDirectoryName(
                Assembly.GetEntryAssembly().Location), StaticFakesSource);
            if (File.Exists(StaticFakesPath))
            {
                var staticFakesJson = File.ReadAllText(StaticFakesPath);
                var staticFakes = JsonConvert.DeserializeObject<Dictionary<string, byte[]>>(
                    staticFakesJson);

                ChallengeMask = staticFakes[nameof(ChallengeMask)];
                FakeMasterSalt = staticFakes[nameof(FakeMasterSalt)];
                FakeMasterKey = staticFakes[nameof(FakeMasterKey)];
                FakeAsymPubKey = staticFakes[nameof(FakeAsymPubKey)];
                FakeAsymPrvKey = staticFakes[nameof(FakeAsymPrvKey)];
                FakeAsymPrvKeyWrapped = staticFakes[nameof(FakeAsymPrvKeyWrapped)];
                Console.WriteLine("Static Fakes Loaded");
            }
            else
            {
                using (var crypto = Crypto.Get())
                {
                    ChallengeMask = Guid.NewGuid().ToByteArray();
                    FakeMasterKey = crypto.DeriveKey("FOOBAR", out FakeMasterSalt);
                    crypto.GenerateKeyPair(out FakeAsymPubKey, out FakeAsymPrvKey);
                    FakeAsymPrvKeyWrapped = crypto.Encrypt(FakeMasterKey, FakeAsymPrvKey);
                    Console.WriteLine("Static Fakes Generated");
                }
            }
        }

        static async Task Main(string[] args) =>
            await CommandLineApplication.ExecuteAsync<Program>(args);

        [Command("export-static-fakes")]
        class ExportStaticFakesCommand
        {
            public int OnExecute(IConsole con)
            {
                var staticFakes = new Dictionary<string, byte[]>
                {
                    [nameof(ChallengeMask)] = ChallengeMask,
                    [nameof(FakeMasterSalt)] = FakeMasterSalt,
                    [nameof(FakeMasterKey)] = FakeMasterKey,
                    [nameof(FakeAsymPubKey)] = FakeAsymPubKey,
                    [nameof(FakeAsymPrvKey)] = FakeAsymPrvKey,
                    [nameof(FakeAsymPrvKeyWrapped)] = FakeAsymPrvKeyWrapped,
                };
                File.WriteAllText(StaticFakesPath, JsonConvert.SerializeObject(staticFakes));
                return 0;
            }
        }


        [Command("list-users")]
        class ListUsersCommand
        {
            public int OnExecute(IConsole con)
            {
                using (var db = new LockboxContext())
                {
                    foreach (var u in db.Users)
                    {
                        con.WriteLine(JsonConvert.SerializeObject(u));
                    }
                }

                return 0;
            }
        }

        [Command("create-user")]
        class CreateUserCommand
        {
            [Option]
            [Required]
            string Email { get; set; }

            [Option]
            [Required]
            string Password { get; set; }

            public async Task<int> OnExecuteAsync(IConsole con)
            {
                // Client-side
                CreateUserStartRequest createUserStartRequ;
                using (var crypto = Crypto.Get())
                {
                    var derivedKey = crypto.DeriveKey(Password, out var derivedSalt);
                    crypto.GenerateKeyPair(derivedKey, out var pubKey, out var prvKeyCrypt);
                    createUserStartRequ = new CreateUserStartRequest
                    {
                        Email = Email,
                        MasterSalt = derivedSalt,
                        AsymPublicKey = pubKey,
                        AsymPrivateKeyWrapped = prvKeyCrypt,
                    };
                }

                // Server-side
                CreateUserStartResponse createUserStartResp;
                using (var crypto = Crypto.Get())
                {
                    var challengeClear = Guid.NewGuid().ToByteArray();
                    var challengeMasked = MemUtil.ApplyXor(challengeClear, ChallengeMask);
                    var challengeCrypt = crypto.EncryptAsym(
                        createUserStartRequ.AsymPublicKey, challengeClear);

                    createUserStartResp = new CreateUserStartResponse
                    {
                        ChallengeToken = SerUtil.PackBytes(
                            SerUtil.Pack(createUserStartRequ),
                            challengeMasked),
                        ChallengeQuestion = challengeCrypt,
                    };
                }

                // Client-side
                CreateUserFinalRequest createUserFinalRequ;
                using (var crypto = Crypto.Get())
                {
                    var derivedKey = crypto.DeriveKey(Password, createUserStartRequ.MasterSalt);
                    var prvKey = crypto.Decrypt(derivedKey, createUserStartRequ.AsymPrivateKeyWrapped);
                    var challenge = crypto.DecryptAsym(createUserStartRequ.AsymPublicKey, prvKey,
                        createUserStartResp.ChallengeQuestion);
                    
                    createUserFinalRequ = new CreateUserFinalRequest
                    {
                        ChallengeToken = createUserStartResp.ChallengeToken,
                        ChallengeAnswer = challenge,
                    };
                }

                // Server-side
                var packed = SerUtil.UnpackBytes(createUserFinalRequ.ChallengeToken);
                if (packed.Length != 2 || packed[0].Length == 0 || packed[1].Length == 0)
                    throw new InvalidDataException("invalid challenge token");
                var origRequ = SerUtil.Unpack<CreateUserStartRequest>(packed[0]);
                var origChallenge = MemUtil.ApplyXor(packed[1], ChallengeMask);

                if (!MemUtil.AreEqual(origChallenge, createUserFinalRequ.ChallengeAnswer))
                    throw new Exception("challenge answer is incorrect");

                var u = new Data.UserEntity
                {
                    Email = origRequ.Email,
                    MasterSalt = origRequ.MasterSalt,
                    AsymPublicKey = origRequ.AsymPublicKey,
                    AsymPrivateKeyWrapped = origRequ.AsymPrivateKeyWrapped,
                };

                using (var db = new LockboxContext())
                {
                    db.Users.Add(u);
                    await db.SaveChangesAsync();
                    con.WriteLine(JsonConvert.SerializeObject(u));
                }

                return 0;
            }
        }

        [Command("list-sessions")]
        class ListSessionsCommand
        {
            [Option]
            string Email { get; set; }

            [Option]
            string User { get; set; }

            [Option("--created-after")]
            DateTime? CreatedAfter { get; set; }

            [Option("--created-before")]
            DateTime? CreatedBefore { get; set; }

            [Option("--expires-after")]
            DateTime? ExpiresAfter { get; set; } = DateTime.Now;

            [Option("--expires-before")]
            DateTime? ExpiresBefore { get; set; }

            [Option]
            int Skip { get; set; } = 0;

            [Option]
            int Take { get; set; } = 100;

            public int OnExecute(IConsole con)
            {
                using (var db = new LockboxContext())
                {
                    var sessions = db.Sessions.Include(x => x.User).AsQueryable();

                    if (!string.IsNullOrEmpty(Email))
                        sessions = sessions.Where(x => x.User.Email == Email);
                    if (User != null)
                        sessions = sessions.Where(x => x.User.Id == Guid.Parse(User));

                    if (CreatedAfter != null)
                        sessions = sessions.Where(x => x.Created > CreatedAfter.Value);
                    if (CreatedBefore != null)
                        sessions = sessions.Where(x => x.Created < CreatedBefore.Value);
                    if (ExpiresAfter != null)
                        sessions = sessions.Where(x => x.Expires > ExpiresAfter.Value);
                    if (ExpiresBefore != null)
                        sessions = sessions.Where(x => x.Expires > ExpiresBefore.Value);

                    sessions = sessions.Skip(Skip).Take(Take)
                        .OrderBy(x => x.Created).OrderBy(x => x.User.Id);

                    foreach (var s in sessions)
                    {
                        con.WriteLine(JsonConvert.SerializeObject(s));
                    }
                }

                return 0;
            }
        }

        [Command("auth")]
        class AuthCommand
        {
            [Option]
            [Required]
            string Email { get; set; }

            [Option]
            [Required]
            string Password { get; set; }

            public async Task<int> OnExecuteAsync(IConsole con)
            {
                // Client-side
                var authStartRequ = new AuthStartRequest
                {
                    Email = Email,
                };

                // Server-side
                Data.UserEntity u;
                using (var db = new LockboxContext())
                {
                    u = db.Users.SingleOrDefault(x => x.Email == authStartRequ.Email);
                }

                // To eliminate timing attacks perform the exact same
                // set of steps regardless if we found a User or not

                var emailHash = Email.ToUTF8().ComputeSHA1();
                var fakeMasterSalt = MemUtil.ApplyXor(FakeMasterSalt, emailHash);
                var fakeAsymPub = MemUtil.ApplyXor(FakeAsymPubKey, emailHash);
                var fakeAsymPrvKeyWrapped = MemUtil.ApplyXor(FakeAsymPrvKeyWrapped, emailHash);

                AuthStartResponse authStartResp;
                if (u == null)
                {
                    authStartResp = new AuthStartResponse
                    {
                        MasterSalt = fakeMasterSalt,
                        AsymPublicKey = fakeAsymPub,
                        AsymPrivateKeyWrapped = FakeAsymPrvKeyWrapped,
                    };
                }
                else
                {
                    authStartResp = new AuthStartResponse
                    {
                        MasterSalt = u.MasterSalt,
                        AsymPublicKey = u.AsymPublicKey,
                        AsymPrivateKeyWrapped = u.AsymPrivateKeyWrapped,
                    };
                }

                using (var crypto = Crypto.Get())
                {
                    var challengeClear = Guid.NewGuid().ToByteArray();
                    var challengeMasked = MemUtil.ApplyXor(challengeClear, ChallengeMask);
                    var challengeCrypt = crypto.EncryptAsym(
                        authStartResp.AsymPublicKey, challengeClear);

                    authStartResp.ChallengeToken = SerUtil.PackBytes(
                        SerUtil.Pack(authStartRequ),
                        challengeMasked);
                    authStartResp.ChallengeQuestion = challengeCrypt;
                }

                // Client-side
                AuthFinalRequest authFinalRequ;
                using (var crypto = Crypto.Get())
                {
                    var derivedKey = crypto.DeriveKey(Password, authStartResp.MasterSalt);
                    var prvKey = crypto.Decrypt(derivedKey, authStartResp.AsymPrivateKeyWrapped);
                    var challenge = crypto.DecryptAsym(authStartResp.AsymPublicKey, prvKey,
                        authStartResp.ChallengeQuestion);
                    
                    authFinalRequ = new AuthFinalRequest
                    {
                        ChallengeToken = authStartResp.ChallengeToken,
                        ChallengeAnswer = challenge,
                    };
                }

                // Server-side
                var packed = SerUtil.UnpackBytes(authFinalRequ.ChallengeToken);
                if (packed.Length != 2 || packed[0].Length == 0 || packed[1].Length == 0)
                    throw new InvalidDataException("invalid challenge token");
                var origRequ = SerUtil.Unpack<AuthStartRequest>(packed[0]);
                var origChallenge = MemUtil.ApplyXor(packed[1], ChallengeMask);

                if (!MemUtil.AreEqual(origChallenge, authFinalRequ.ChallengeAnswer))
                    throw new Exception("challenge answer is incorrect");

                AuthFinalResponse authFinalResp;
                using (var db = new LockboxContext())
                {
                    db.Attach(u);
                    var ses = new SessionEntity
                    {
                        AccessId = Guid.NewGuid(),
                        User = u,
                        Created = DateTime.Now,
                        Expires = DateTime.Now.AddMinutes(15),
                    };
                    db.Sessions.Add(ses);
                    await db.SaveChangesAsync();

                    authFinalResp = new AuthFinalResponse
                    {
                        AclToken = ses.Id.ToString(),
                    };
                }

                // Client-side
                var cachedToken = new CachedAclToken
                {
                    Token = authFinalResp.AclToken,
                    MasterSalt = authStartResp.MasterSalt,
                };
                File.WriteAllText(AclTokenCache, JsonConvert.SerializeObject(cachedToken));
                con.WriteLine("ACL Token Cached");

                return 0;
           }
        }

        class CachedAclToken
        {
            public string Token { get; set; }
            public byte[] MasterSalt { get; set; }
        }

        [Command("list-boxes")]
        class ListBoxesCommand
        {
            [Option]
            string Token { get; set; }

            public int OnExecute(IConsole con)
            {
                // Client-side
                if (string.IsNullOrEmpty(Token) && File.Exists(AclTokenCache))
                {
                    var cachedTokenJson = File.ReadAllText(AclTokenCache);
                    var cachedToken = JsonConvert.DeserializeObject<CachedAclToken>(cachedTokenJson);
                    Token = cachedToken.Token;
                }
                if (string.IsNullOrEmpty(Token))
                {
                    con.Error.WriteLine("cached token is missing or expired, token must be specified");
                    return -1;
                }

                // Server-side
                using (var db = new LockboxContext())
                {
                    var sid = Guid.Parse(Token);
                    var ses = db.Sessions.Include(x => x.User)
                        .SingleOrDefault(x => x.Id == sid);
                    var now = DateTime.Now;
                    if (ses == null || now < ses.Created || now > ses.Expires)
                        throw new Exception("invalid, missing or expired session");
                    
                    foreach (var ub in db.UserBoxes.Where(x => x.User == ses.User))
                    {
                        con.WriteLine(JsonConvert.SerializeObject(ub));
                    }
                }

                return 0;
            }
        }

        [Command("create-box")]
        class CreateBoxCommand
        {
            [Option]
            string Token { get; set; }

            [Option]
            [Required]
            string Password { get; set; }

            [Option]
            [Required]
            string Label { get; set; }

            public int OnExecute(IConsole con)
            {
                // Client-side
                if (string.IsNullOrEmpty(Token) && File.Exists(AclTokenCache))
                {
                    var cachedTokenJson = File.ReadAllText(AclTokenCache);
                    var cachedToken = JsonConvert.DeserializeObject<CachedAclToken>(cachedTokenJson);
                    Token = cachedToken.Token;
                }
                if (string.IsNullOrEmpty(Token))
                {
                    con.Error.WriteLine("cached token is missing or expired, token must be specified");
                    return -1;
                }
                var getSelfRequ = new GetSelfRequest();

                // Server-side
                var getSelfResp = new GetSelfResponse();
                using (var crypto = Crypto.Get())
                using (var db = new LockboxContext())
                {
                    var sid = Guid.Parse(Token);
                    var ses = db.Sessions.Include(x => x.User)
                        .SingleOrDefault(x => x.Id == sid);
                    var now = DateTime.Now;
                    if (ses == null || now < ses.Created || now > ses.Expires)
                        throw new Exception("invalid, missing or expired session");
                
                    getSelfResp.MasterSalt = ses.User.MasterSalt;
                    getSelfResp.AsymPublicKey = ses.User.AsymPublicKey;
                    getSelfResp.AsymPrivateKeyWrapped = ses.User.AsymPrivateKeyWrapped;
                }

                // Client-side
                var createBoxRequ = new CreateBoxRequest
                {
                    Label = Label,
                };
                using (var crypto = Crypto.Get())
                {
                    var mk = crypto.DeriveKey(Password, getSelfResp.MasterSalt);
                    var bk = crypto.GenerateKey();
                    createBoxRequ.KeyWrapped = crypto.EncryptAsym(getSelfResp.AsymPublicKey, bk);
                };

                // Server-side
                using (var crypto = Crypto.Get())
                using (var db = new LockboxContext())
                {
                    var sid = Guid.Parse(Token);
                    var ses = db.Sessions.Include(x => x.User)
                        .SingleOrDefault(x => x.Id == sid);
                    var now = DateTime.Now;
                    if (ses == null || now < ses.Created || now > ses.Expires)
                        throw new Exception("invalid, missing or expired session");

                    var b = new Data.BoxEntity
                    {
                        Owner = ses.User,
                        Label = Label,
                    };
                    db.Boxes.Add(b);
                    var ub = new Data.UserBoxEntity
                    {
                        User = ses.User,
                        Box = b,
                        KeyWrapped = createBoxRequ.KeyWrapped,
                    };
                    db.UserBoxes.Add(ub);
                    db.SaveChanges();
                }

                return 0;
            }
        }

        [Command("list-entries")]
        class ListEntriesCommand
        {
            [Option]
            string Token { get; set; }

            [Option]
            [Required]
            string Box { get; set; }

            public int OnExecute(IConsole con)
            {
                // Client-side
                if (string.IsNullOrEmpty(Token) && File.Exists(AclTokenCache))
                {
                    var cachedTokenJson = File.ReadAllText(AclTokenCache);
                    var cachedToken = JsonConvert.DeserializeObject<CachedAclToken>(cachedTokenJson);
                    Token = cachedToken.Token;
                }
                if (string.IsNullOrEmpty(Token))
                {
                    con.Error.WriteLine("cached token is missing or expired, token must be specified");
                    return -1;
                }

                // Server-side
                using (var db = new LockboxContext())
                {
                    var sid = Guid.Parse(Token);
                    var ses = db.Sessions.Include(x => x.User)
                        .SingleOrDefault(x => x.Id == sid);
                    var now = DateTime.Now;
                    if (ses == null || now < ses.Created || now > ses.Expires)
                        throw new Exception("invalid, missing or expired session");
                    
                    var userBox = db.UserBoxes.Where(x => x.User == ses.User && x.Box.Label == Box);
                    var entries = db.Entries.Join(userBox, x => x.Box, y => y.Box, (x, y) => x);

                    foreach (var e in entries)
                    {
                        con.WriteLine(JsonConvert.SerializeObject(e));
                    }
                }

                return 0;
            }
        }

        [Command("create-entry")]
        class CreateEntryCommand
        {
            [Option]
            string Token { get; set; }

            [Option]
            [Required]
            string Box { get; set; }

            [Option]
            [Required]
            string Password { get; set; }

            [Option]
            [Required]
            string Label { get; set; }

            [Option]
            string[] Value { get; set; } = new string[0];

            [Option]
            string[] Secret { get; set; } = new string[0];

            public int OnExecute(IConsole con)
            {
                // Client-side
                if (string.IsNullOrEmpty(Token) && File.Exists(AclTokenCache))
                {
                    var cachedTokenJson = File.ReadAllText(AclTokenCache);
                    var cachedToken = JsonConvert.DeserializeObject<CachedAclToken>(cachedTokenJson);
                    Token = cachedToken.Token;
                }
                if (string.IsNullOrEmpty(Token))
                {
                    con.Error.WriteLine("cached token is missing or expired, token must be specified");
                    return -1;
                }
                var getSelfBoxRequ = new GetSelfBoxRequest { Box = Box, };

                // Server-side
                var getSelfBoxResp = new GetSelfBoxResponse();
                using (var db = new LockboxContext())
                {
                    var sid = Guid.Parse(Token);
                    var ses = db.Sessions.Include(x => x.User)
                        .SingleOrDefault(x => x.Id == sid);
                    var now = DateTime.Now;
                    if (ses == null || now < ses.Created || now > ses.Expires)
                        throw new Exception("invalid, missing or expired session");

                    var userBox = db.UserBoxes.SingleOrDefault(x => x.Box.Label == Box);
                    if (userBox == null)
                        throw new Exception("box not found");

                    getSelfBoxResp.MasterSalt = ses.User.MasterSalt;
                    getSelfBoxResp.AsymPublicKey = ses.User.AsymPublicKey;
                    getSelfBoxResp.AsymPrivateKeyWrapped = ses.User.AsymPrivateKeyWrapped;
                    getSelfBoxResp.BoxKeyWrapped = userBox.KeyWrapped;
                }

                // Client-side
                var createEntryRequ = new CreateEntryRequest
                {
                    Label = Label,
                };
                using (var crypto = Crypto.Get())
                {
                    var mk = crypto.DeriveKey(Password, getSelfBoxResp.MasterSalt);
                    var pk = crypto.Decrypt(mk, getSelfBoxResp.AsymPrivateKeyWrapped);
                    var bk = crypto.DecryptAsym(getSelfBoxResp.AsymPublicKey, pk,
                        getSelfBoxResp.BoxKeyWrapped);

                    if (Value?.Length > 0)
                    {
                        createEntryRequ.Values = new Dictionary<string, string>();
                        foreach (var kv in Value)
                        {
                            var kvSplit = kv.Split("=", 2);
                            createEntryRequ.Values[kvSplit[0]] = kvSplit[1];
                        }
                    }

                    if (Secret?.Length > 0)
                    {
                        createEntryRequ.Secrets = new Dictionary<string, byte[]>();
                        foreach (var kv in Secret)
                        {
                            var kvSplit = kv.Split("=", 2);
                            var val = crypto.Encrypt(bk, kvSplit[1].ToUTF8());
                            createEntryRequ.Secrets[kvSplit[0]] = val;
                        }
                    }
                };

                // Server-side
                using (var db = new LockboxContext())
                {
                    var sid = Guid.Parse(Token);
                    var ses = db.Sessions.Include(x => x.User)
                        .SingleOrDefault(x => x.Id == sid);
                    var now = DateTime.Now;
                    if (ses == null || now < ses.Created || now > ses.Expires)
                        throw new Exception("invalid, missing or expired session");
                    
                    var userBox = db.UserBoxes.Include(x => x.Box)
                        .SingleOrDefault(x => x.User == ses.User && x.Box.Label == Box);
                    if (userBox == null)
                        throw new Exception("box not found");

                    var entry = new Data.EntryEntity
                    {
                        Box = userBox.Box,
                        Label = createEntryRequ.Label,
                        Ver = 1,
                    };
                    db.Entries.Add(entry);

                    if (createEntryRequ.Values?.Count > 0)
                    {
                        foreach (var kv in createEntryRequ.Values)
                        {
                            var f = new Data.FieldEntity
                            {
                                Entry = entry,
                                Name = kv.Key,
                                ClearValue = kv.Value,
                                Ver = 1,
                            };
                            db.Fields.Add(f);
                        }
                    }
                    if (createEntryRequ.Secrets?.Count > 0)
                    {
                        foreach (var kv in createEntryRequ.Secrets)
                        {
                            var f = new Data.FieldEntity
                            {
                                Entry = entry,
                                Name = kv.Key,
                                CryptValue = kv.Value,
                                Ver = 1,
                            };
                            db.Fields.Add(f);
                        }
                    }
                    db.SaveChanges();
                }

                return 0;
            }
        }

        [Command("read-entry")]
        class ReadEntryCommand
        {
            [Option]
            string Token { get; set; }

            [Option]
            [Required]
            string Box { get; set; }

            [Option]
            [Required]
            string Entry { get; set; }

            [Option]
            [Required]
            string Password { get; set; }

            public int OnExecute(IConsole con)
            {
                // Client-side
                if (string.IsNullOrEmpty(Token) && File.Exists(AclTokenCache))
                {
                    var cachedTokenJson = File.ReadAllText(AclTokenCache);
                    var cachedToken = JsonConvert.DeserializeObject<CachedAclToken>(cachedTokenJson);
                    Token = cachedToken.Token;
                }
                if (string.IsNullOrEmpty(Token))
                {
                    con.Error.WriteLine("cached token is missing or expired, token must be specified");
                    return -1;
                }
                var getSelfBoxEntryRequ = new GetSelfBoxEntryRequest { Box = Box, Entry = Entry };

                // Server-side
                var getSelfBoxEntryResp = new GetSelfBoxEntryResponse();
                using (var db = new LockboxContext())
                {
                    var sid = Guid.Parse(Token);
                    var ses = db.Sessions.Include(x => x.User)
                        .SingleOrDefault(x => x.Id == sid);
                    var now = DateTime.Now;
                    if (ses == null || now < ses.Created || now > ses.Expires)
                        throw new Exception("invalid, missing or expired session");

                    var userBox = db.UserBoxes.Include(x => x.Box)
                        .SingleOrDefault(x => x.User == ses.User && x.Box.Label == Box);
                    if (userBox?.Box == null)
                        throw new Exception("box not found");

                    var entry = db.Entries.Include(x => x.Box)
                        .SingleOrDefault(x => x.Box == userBox.Box
                            && x.Label == getSelfBoxEntryRequ.Entry);
                    if (entry?.Box == null)
                        throw new Exception("entry not found");

                    getSelfBoxEntryResp.MasterSalt = ses.User.MasterSalt;
                    getSelfBoxEntryResp.AsymPublicKey = ses.User.AsymPublicKey;
                    getSelfBoxEntryResp.AsymPrivateKeyWrapped = ses.User.AsymPrivateKeyWrapped;
                    getSelfBoxEntryResp.BoxKeyWrapped = userBox.KeyWrapped;

                    var fields = db.Fields.Include(x => x.Entry)
                        .Where(x => x.Entry == entry && x.Ver == x.Entry.Ver).ToList();
                    foreach (var f in fields)
                    {
                        if (f.CryptValue != null)
                        {
                            if (getSelfBoxEntryResp.Secrets == null)
                                getSelfBoxEntryResp.Secrets = new Dictionary<string, byte[]>();
                            getSelfBoxEntryResp.Secrets[f.Name] = f.CryptValue;
                        }
                        else if (f.ClearValue != null)
                        {
                            if (getSelfBoxEntryResp.Values == null)
                                getSelfBoxEntryResp.Values = new Dictionary<string, string>();
                            getSelfBoxEntryResp.Values[f.Name] = f.ClearValue;
                        }
                    }
                }

                // Client-side
                using (var crypto = Crypto.Get())
                {
                    var mk = crypto.DeriveKey(Password, getSelfBoxEntryResp.MasterSalt);
                    var pk = crypto.Decrypt(mk, getSelfBoxEntryResp.AsymPrivateKeyWrapped);
                    var bk = crypto.DecryptAsym(getSelfBoxEntryResp.AsymPublicKey, pk,
                        getSelfBoxEntryResp.BoxKeyWrapped);

                    if (getSelfBoxEntryResp.Values?.Count > 0)
                    {
                        foreach (var v in getSelfBoxEntryResp.Values)
                        {
                            con.WriteLine("[{0}]=[{1}]", v.Key, v.Value);
                        }
                    }

                    if (getSelfBoxEntryResp.Secrets?.Count > 0)
                    {
                        foreach (var v in getSelfBoxEntryResp.Secrets)
                        {
                            con.WriteLine("[{0}]=[{1}]", v.Key, crypto.Decrypt(bk, v.Value).FromUTF8());
                        }
                    }
                };

                return 0;
            }
        }
    }
}
