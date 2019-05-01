﻿// <auto-generated />
using System;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using Zyborg.Lockbox.Server.Data.EF;

namespace Zyborg.Lockbox.Server.Data.EF.Migrations
{
    [DbContext(typeof(LockboxContext))]
    partial class LockboxContextModelSnapshot : ModelSnapshot
    {
        protected override void BuildModel(ModelBuilder modelBuilder)
        {
#pragma warning disable 612, 618
            modelBuilder
                .HasAnnotation("ProductVersion", "2.2.4-servicing-10062");

            modelBuilder.Entity("Zyborg.Lockbox.Server.Data.BoxEntity", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd();

                    b.Property<string>("Label")
                        .IsRequired();

                    b.Property<Guid?>("OwnerId")
                        .IsRequired();

                    b.HasKey("Id");

                    b.HasAlternateKey("OwnerId", "Label");

                    b.ToTable("Boxes");
                });

            modelBuilder.Entity("Zyborg.Lockbox.Server.Data.EntryEntity", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd();

                    b.Property<Guid?>("BoxId")
                        .IsRequired();

                    b.Property<string>("Label")
                        .IsRequired();

                    b.Property<int>("Ver");

                    b.HasKey("Id");

                    b.HasAlternateKey("BoxId", "Label");

                    b.ToTable("Entries");
                });

            modelBuilder.Entity("Zyborg.Lockbox.Server.Data.FieldEntity", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd();

                    b.Property<string>("ClearValue");

                    b.Property<byte[]>("CryptValue");

                    b.Property<Guid?>("EntryId")
                        .IsRequired();

                    b.Property<string>("Name")
                        .IsRequired();

                    b.Property<int>("Ver");

                    b.HasKey("Id");

                    b.HasAlternateKey("EntryId", "Name", "Ver");

                    b.ToTable("Fields");
                });

            modelBuilder.Entity("Zyborg.Lockbox.Server.Data.SessionEntity", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd();

                    b.Property<Guid>("AccessId");

                    b.Property<DateTime>("Created");

                    b.Property<DateTime>("Expires");

                    b.Property<Guid?>("UserId")
                        .IsRequired();

                    b.HasKey("Id");

                    b.HasAlternateKey("AccessId");

                    b.HasIndex("UserId");

                    b.ToTable("Sessions");
                });

            modelBuilder.Entity("Zyborg.Lockbox.Server.Data.UserBoxEntity", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd();

                    b.Property<Guid?>("BoxId")
                        .IsRequired();

                    b.Property<byte[]>("KeyWrapped");

                    b.Property<Guid?>("UserId")
                        .IsRequired();

                    b.HasKey("Id");

                    b.HasAlternateKey("UserId", "BoxId");

                    b.HasIndex("BoxId");

                    b.ToTable("UserBoxes");
                });

            modelBuilder.Entity("Zyborg.Lockbox.Server.Data.UserEntity", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd();

                    b.Property<byte[]>("AsymPrivateKeyWrapped");

                    b.Property<byte[]>("AsymPublicKey");

                    b.Property<string>("Email")
                        .IsRequired();

                    b.Property<byte[]>("MasterSalt");

                    b.Property<byte[]>("SigPrivateKeyWrapped");

                    b.Property<byte[]>("SigPublicKey");

                    b.HasKey("Id");

                    b.HasAlternateKey("Email");

                    b.ToTable("Users");
                });

            modelBuilder.Entity("Zyborg.Lockbox.Server.Data.BoxEntity", b =>
                {
                    b.HasOne("Zyborg.Lockbox.Server.Data.UserEntity", "Owner")
                        .WithMany()
                        .HasForeignKey("OwnerId")
                        .OnDelete(DeleteBehavior.Cascade);
                });

            modelBuilder.Entity("Zyborg.Lockbox.Server.Data.EntryEntity", b =>
                {
                    b.HasOne("Zyborg.Lockbox.Server.Data.BoxEntity", "Box")
                        .WithMany()
                        .HasForeignKey("BoxId")
                        .OnDelete(DeleteBehavior.Cascade);
                });

            modelBuilder.Entity("Zyborg.Lockbox.Server.Data.FieldEntity", b =>
                {
                    b.HasOne("Zyborg.Lockbox.Server.Data.EntryEntity", "Entry")
                        .WithMany()
                        .HasForeignKey("EntryId")
                        .OnDelete(DeleteBehavior.Cascade);
                });

            modelBuilder.Entity("Zyborg.Lockbox.Server.Data.SessionEntity", b =>
                {
                    b.HasOne("Zyborg.Lockbox.Server.Data.UserEntity", "User")
                        .WithMany()
                        .HasForeignKey("UserId")
                        .OnDelete(DeleteBehavior.Cascade);
                });

            modelBuilder.Entity("Zyborg.Lockbox.Server.Data.UserBoxEntity", b =>
                {
                    b.HasOne("Zyborg.Lockbox.Server.Data.BoxEntity", "Box")
                        .WithMany()
                        .HasForeignKey("BoxId")
                        .OnDelete(DeleteBehavior.Cascade);

                    b.HasOne("Zyborg.Lockbox.Server.Data.UserEntity", "User")
                        .WithMany()
                        .HasForeignKey("UserId")
                        .OnDelete(DeleteBehavior.Cascade);
                });
#pragma warning restore 612, 618
        }
    }
}