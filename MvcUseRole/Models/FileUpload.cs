using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;


namespace MvcUseRole.Models
{
    public class FileUpload
    {
        public int ID { get; set; }
        public string FileName { get; set; }
        public string FilePath { get; set; }
        public string UserId { get; set; }
        public bool? Approve { get; set; }
    }
}