using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Linq;
using System.Web;
using MvcUseRole.Models;
using System.Data.Entity.ModelConfiguration.Conventions;

namespace MvcUseRole.DAL
{
    public class AttendanceDB : DbContext
    {
        public DbSet<FileUpload> FileUploads { get; set; }
    }
}