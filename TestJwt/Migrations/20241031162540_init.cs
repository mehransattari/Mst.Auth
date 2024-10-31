using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace TestJwt.Migrations
{
    /// <inheritdoc />
    public partial class init : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "Users",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Username = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Password = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Role = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    RefreshToken = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    RefreshTokenExpiryTime = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Users", x => x.Id);
                });

            migrationBuilder.InsertData(
                table: "Users",
                columns: new[] { "Id", "Password", "RefreshToken", "RefreshTokenExpiryTime", "Role", "Username" },
                values: new object[,]
                {
                    { 1, "$2a$11$k9O8w.Ak1zZUcegqUX9fw.059Eyw2RxBohXHpEtYG9B3kSgIHkJLy", "5eb22269-0a4c-496d-b6d8-bdc6925c892e", new DateTime(2024, 11, 7, 19, 55, 39, 692, DateTimeKind.Local).AddTicks(2783), "Admin", "admin" },
                    { 2, "$2a$11$B.IWkNcA/x0aflMLAjqAeeF9RAAX.4ITiDvl62/hNzCzCdgw6CxK2", "d0bc566d-f529-4724-ac81-299d7c0771a8", new DateTime(2024, 11, 7, 19, 55, 39, 860, DateTimeKind.Local).AddTicks(3799), "User", "user" }
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "Users");
        }
    }
}
