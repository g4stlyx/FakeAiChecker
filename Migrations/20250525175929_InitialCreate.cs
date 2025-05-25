using System;
using Microsoft.EntityFrameworkCore.Migrations;
using MySql.EntityFrameworkCore.Metadata;

#nullable disable

namespace FakeAiChecker.Migrations
{
    /// <inheritdoc />
    public partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AlterDatabase()
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "AuditLogs",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("MySQL:ValueGenerationStrategy", MySQLValueGenerationStrategy.IdentityColumn),
                    SessionId = table.Column<string>(type: "longtext", nullable: false),
                    Action = table.Column<string>(type: "longtext", nullable: false),
                    Details = table.Column<string>(type: "longtext", nullable: false),
                    Timestamp = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    UserIpAddress = table.Column<string>(type: "longtext", nullable: true),
                    UserAgent = table.Column<string>(type: "longtext", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AuditLogs", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "ScanResults",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("MySQL:ValueGenerationStrategy", MySQLValueGenerationStrategy.IdentityColumn),
                    SessionId = table.Column<string>(type: "longtext", nullable: false),
                    FileName = table.Column<string>(type: "longtext", nullable: false),
                    FilePath = table.Column<string>(type: "longtext", nullable: false),
                    ScanDate = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    FakeAiPercentage = table.Column<int>(type: "int", nullable: false),
                    HumanPercentage = table.Column<int>(type: "int", nullable: false),
                    UserIpAddress = table.Column<string>(type: "longtext", nullable: true),
                    UserAgent = table.Column<string>(type: "longtext", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ScanResults", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "SecretFindings",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("MySQL:ValueGenerationStrategy", MySQLValueGenerationStrategy.IdentityColumn),
                    ScanResultId = table.Column<int>(type: "int", nullable: false),
                    SecretType = table.Column<string>(type: "longtext", nullable: false),
                    FileName = table.Column<string>(type: "longtext", nullable: false),
                    FilePath = table.Column<string>(type: "longtext", nullable: false),
                    SecretValue = table.Column<string>(type: "longtext", nullable: false),
                    Context = table.Column<string>(type: "longtext", nullable: false),
                    FoundAt = table.Column<DateTime>(type: "datetime(6)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SecretFindings", x => x.Id);
                    table.ForeignKey(
                        name: "FK_SecretFindings_ScanResults_ScanResultId",
                        column: x => x.ScanResultId,
                        principalTable: "ScanResults",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateIndex(
                name: "IX_SecretFindings_ScanResultId",
                table: "SecretFindings",
                column: "ScanResultId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AuditLogs");

            migrationBuilder.DropTable(
                name: "SecretFindings");

            migrationBuilder.DropTable(
                name: "ScanResults");
        }
    }
}
