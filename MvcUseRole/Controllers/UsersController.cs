using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using MvcUseRole.DAL;
using MvcUseRole.Models;
using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.IO;
using System.Linq;
using System.Net;
using System.Web;
using System.Web.Mvc;

namespace MvcUseRole.Controllers
{
    public class UsersController : Controller
    {
        ApplicationDbContext db = new ApplicationDbContext();
        private AttendanceDB db2 = new AttendanceDB();
        // GET: Users
        public Boolean isAdminUser()
        {
            if (User.Identity.IsAuthenticated)
            {
                var user = User.Identity;
                ApplicationDbContext context = new ApplicationDbContext();
                var UserManager = new UserManager<ApplicationUser>(new UserStore<ApplicationUser>(context));
                var s = UserManager.GetRoles(user.GetUserId());
                if (s[0].ToString() == "Admin")
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }
            return false;
        }

        public ActionResult Index()
        {
            if (User.Identity.IsAuthenticated)
            {
                var user = User.Identity;
                ViewBag.Name = user.Name;
                //	ApplicationDbContext context = new ApplicationDbContext();
                //	var UserManager = new UserManager<ApplicationUser>(new UserStore<ApplicationUser>(context));

                //var s=	UserManager.GetRoles(user.GetUserId());
                ViewBag.displayMenu = "No";

                if (isAdminUser())
                {
                    ViewBag.displayMenu = "Yes";

                    ViewBag.admin = (from a in db.Users select a).ToList();
                }
                return View();
            }
            else
            {
                ViewBag.Name = "Not Logged IN";
            }
            return View();
        }

        public ActionResult Status(string id)
        {
            var UserManager = new UserManager<ApplicationUser>(new UserStore<ApplicationUser>(db));
            var userId = UserManager.FindById(id).Id;
            if (UserManager.GetLockoutEnabled(userId) == true)
            {
                UserManager.SetLockoutEnabled(userId, false);
            }
            else
            {
                UserManager.SetLockoutEnabled(userId, true);
            }
            return RedirectToAction("Index");
        }

        public ActionResult Delete(string id)
        {
            var find = (from finding in db.Users where finding.Id == id select finding).ToList();
            ViewBag.delete = find;

            return View();
        }

        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public ActionResult DeleteConfirmed(string id)
        {
            var deleted = db.Users.Find(id);
            db.Users.Remove(deleted);
            db.SaveChanges();
            TempData["delete"] = "Data Has Been Delete";

            return RedirectToAction("Index");
        }

        public ActionResult ManageUpload()
        {
            var show = (from item in db2.FileUploads select item).ToList();
            ViewBag.look = show;
            return View();
        }

        // Delete Upload
        public ActionResult DeleteUpload(int id)
        {
            var find = (from finding in db2.FileUploads where finding.ID == id select finding).ToList();
            ViewBag.deleteU = find;

            return View();
        }

        [HttpPost, ActionName("DeleteUpload")]
        [ValidateAntiForgeryToken]
        public ActionResult DeleteUploadConfirmed(int id)
        {
            var deleted = db2.FileUploads.Find(id);
            db2.FileUploads.Remove(deleted);
            db2.SaveChanges();

            return RedirectToAction("ManageUpload");
        }

        // Download File
        public ActionResult Download(int id)
        {
            var download = (from file in db2.FileUploads where file.ID == id select new { file.FileName, file.FilePath }).SingleOrDefault();
            if (download != null)
            {
                // remove this line if you want file download on the same pages
                Response.AddHeader("content-disposition", "inline; filename=" + download.FileName);
                return File(download.FilePath, "application/octet-stream");
            }
            else
            {
                return null;
            }
        }

        // Approve File
        public ActionResult Approve(int id)
        {
            var find = db2.FileUploads.Find(id);
            if (find.Approve == true)
            {
                find.Approve = false;
            }
            else
            {
                find.Approve = true;
            }
            db2.Entry(find).State = EntityState.Modified;
            db2.SaveChanges();
            return RedirectToAction("ManageUpload");
        }
    }
}