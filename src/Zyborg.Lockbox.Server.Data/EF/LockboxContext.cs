using Microsoft.EntityFrameworkCore;

namespace Zyborg.Lockbox.Server.Data.EF
{
    public class LockboxContext : DbContext
    {
        public const string BoxOwnerProperty = nameof(BoxEntity.Owner) + "Id";
        public const string UserBoxUserProperty = nameof(UserBoxEntity.User) + "Id";
        public const string UserBoxBoxProperty = nameof(UserBoxEntity.Box) + "Id";
        public const string EntryBoxProperty = nameof(EntryEntity.Box) + "Id";
        public const string FieldEntryProperty = nameof(FieldEntity.Entry) + "Id";
        public const string SessionUserProperty = nameof(SessionEntity.User) + "Id";

        public DbSet<UserEntity> Users { get; set; }
        public DbSet<BoxEntity> Boxes { get; set; }
        public DbSet<UserBoxEntity> UserBoxes { get; set; }
        public DbSet<EntryEntity> Entries { get; set; }
        public DbSet<FieldEntity> Fields { get; set; }
        public DbSet<SessionEntity> Sessions { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<UserEntity>().Property(e => e.Email).IsRequired();
            modelBuilder.Entity<UserEntity>().HasAlternateKey(e => e.Email);

            modelBuilder.Entity<BoxEntity>().HasOne(e => e.Owner);
            modelBuilder.Entity<BoxEntity>().Property(BoxOwnerProperty).IsRequired();
            modelBuilder.Entity<BoxEntity>().Property(e => e.Label).IsRequired();
            modelBuilder.Entity<BoxEntity>().HasAlternateKey(
                BoxOwnerProperty, nameof(BoxEntity.Label));

            modelBuilder.Entity<UserBoxEntity>().HasOne(e => e.User);
            modelBuilder.Entity<UserBoxEntity>().Property(UserBoxUserProperty).IsRequired();
            modelBuilder.Entity<UserBoxEntity>().HasOne(e => e.Box);
            modelBuilder.Entity<UserBoxEntity>().Property(UserBoxBoxProperty).IsRequired();
            modelBuilder.Entity<UserBoxEntity>().HasAlternateKey(
                UserBoxUserProperty, UserBoxBoxProperty);

            modelBuilder.Entity<EntryEntity>().HasOne(e => e.Box);
            modelBuilder.Entity<EntryEntity>().Property(EntryBoxProperty).IsRequired();
            modelBuilder.Entity<EntryEntity>().Property(e => e.Label).IsRequired();
            modelBuilder.Entity<EntryEntity>().HasAlternateKey(
                EntryBoxProperty, nameof(EntryEntity.Label));

            modelBuilder.Entity<FieldEntity>().HasOne(e => e.Entry);
            modelBuilder.Entity<FieldEntity>().Property(FieldEntryProperty).IsRequired();
            modelBuilder.Entity<FieldEntity>().Property(e => e.Name).IsRequired();
            modelBuilder.Entity<FieldEntity>().Property(e => e.Ver).IsRequired();
            modelBuilder.Entity<FieldEntity>().HasAlternateKey(
                FieldEntryProperty, nameof(FieldEntity.Name), nameof(FieldEntity.Ver));

            modelBuilder.Entity<SessionEntity>().HasOne(e => e.User);
            modelBuilder.Entity<SessionEntity>().Property(SessionUserProperty).IsRequired();
            modelBuilder.Entity<SessionEntity>().Property(e => e.AccessId).IsRequired();
            modelBuilder.Entity<SessionEntity>().HasAlternateKey(e => e.AccessId);
        }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            optionsBuilder.UseSqlite("Data Source=sample.lkbx");
        }
    }
}