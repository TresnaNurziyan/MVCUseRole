namespace MvcUseRole.Migrations
{
    using System;
    using System.Data.Entity.Migrations;
    
    public partial class File : DbMigration
    {
        public override void Up()
        {
            CreateTable(
                "dbo.FileUploads",
                c => new
                {
                    ID = c.Int(nullable: false, identity: true),
                    FileName = c.String(),
                    FilePath = c.String(),
                    UserId = c.String(),
                    Approve = c.Boolean(nullable: true),
                })
                .PrimaryKey(t => t.ID);
        }
        
        public override void Down()
        {
            DropTable("dbo.FileUploads");
        }
    }
}
