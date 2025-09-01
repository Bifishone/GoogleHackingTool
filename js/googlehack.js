        function do_google_search(type) {
            site = document.getElementById('sercHead').value;

            url1 = 'https://www.google.com/search?q=';
            url2 = url1 + 'site:' + site;
            switch (type) {
                // 目录遍历漏洞
                case 1:
                    url = url2 + '+intitle:index.of';
                    break;
                    
                // 可能存在的注入点漏洞 inurl:.php?id=1
                case 2:
                    url = url2 + ' (inurl:php?id= | inurl:aspx?id= | inurl:jsp?id= | inurl:asp?id= )';
                    break;
                    
                // 查找文件上传漏洞
                case 3:
                    url = url2 + ' inurl:file|load|editor|uploadfile';
                    break;
                    
                // 登录页面
                case 4:
                    url = url2 + '+inurl:login+|+inurl:admin+|+inurl:manage+|+inurl:system+|+inurl:backend+|+intitle:登陆+|+intitle:后台+|+intitle:管理+|+intitle:认证';
                    break;
                    
                // 可能存在的用户敏感信息泄露（侧重用户）
                case 5:
                    url = url2 + ' intext:管理|后台|登陆|用户名|密码|验证码|系统|帐号|admin|login|sys|managetem|password|username';
                    break;
                    
                // 可能存在的敏感信息泄露（侧重网站）
                case 6:
                    url = url2 + ' (intitle:"index of" (etc|.sh_history|.bash_history|passwd|people.lst|pwd.db|etc/shadow|spwd|master.passwd|htpasswd|admin|data)) | (inurl:service.pwd) | (intitle:phpmyadmin intext:"Create new database") | (intitle:"php shell*" "Enable stderr" filetype:php) | (intitle:"error occurred" intext:"ODBC request where (select|insert)") | (intitle:"index.of" filetype:log)';
                    break;
                    
                // 常见报错页面泄露
                case 7:
                    url = url2 + ' (intext:"org.springframework.beans.factory.BeanCreationException" | intext:"org.springframework.web.bind.annotation.support.HandlerMethodInvocationException" | intext:"java.lang.NullPointerException" | intext:"java.lang.ClassCastException" | intext:"java.sql.SQLException" | intext:"com.mysql.jdbc.exceptions" | intext:"SQLSTATE" | intext:"Microsoft JET Database Engine error" | intext:"Parse error: syntax error" | intext:"Fatal error: Call to undefined function" | intext:"Warning: mysql_connect()" | intext:"Stack trace:" | intext:"at org.springframework" | intext:"in /var/www/" | intext:"C:\inetpub\wwwroot\" | intext:"HibernateException" | intext:"TransactionRequiredException" | intext:"DataIntegrityViolationException" | intext:"ConstraintViolationException" | intext:"NoSuchBeanDefinitionException" | intext:"MethodArgumentNotValidException" | intext:"BadCredentialsException" | intext:"AccessDeniedException" | intext:"MaxUploadSizeExceededException")';
                    break;
                    
                // 查找数据库、备份、配置等文件(杂)
                case 8:
                    url = url2 + ' (inurl:editor/db/|eWebEditor/db/|bbs/data/|databackup/|blog/data/|okedata|bbs/database/|conn.asp|inc/conn.asp|viewerframe?mode=|db|mdb|config.txt|bash_history|temp|tmp|backup|bak|database/PowerEasy4.mdb|database/PowerEasy5.mdb|database/PowerEasy6.mdb|database/PowerEasy2005.mdb|database/PowerEasy2006.mdb|database/PE_Region.mdb|data/dvbbs7.mdb|databackup/dvbbs7.mdb|bbs/databackup/dvbbs7.mdb|data/zm_marry.asp|admin/data/qcdn_news.mdb|firend.mdb|database/newcloud6.mdb|database/%23newasp.mdb|blogdata/L-BLOG.mdb|blog/blogdata/L-BLOG.mdb|database/bbsxp.mdb|bbs/database/bbsxp.mdb|access/sf2.mdb|data/Leadbbs.mdb|bbs/Data/LeadBBS.mdb|bbs/access/sf2.mdb|fdnews.asp|bbs/fdnews.asp|admin/ydxzdate.asa|data/down.mdb|data/db1.mdb|database/Database.mdb|db/xzjddown.mdb|db/play.asp|mdb.asp|admin/data/user.asp|data_jk/joekoe_data.asp|data/news3000.asp|data/appoen.mdb|data/12912.asp|database.asp|download.mdb|dxxobbs/mdb/dxxobbs.mdb|db/6k.asp|database/snowboy.mdb|database/%23mmdata.mdb|editor/db/ewebeditor.mdb|eWebEditor/db/ewebeditor.mdb) | (inurl:data filetype:mdb)';
                    break;
                    
                // 身份信息泄露EDU
                case 9:
                    url = url2 + ' ' + '"身份证" "学生证" "1992" "1993" "1994" "1995" "1996" "1997" "1998" "1999" "2000"';
                    break;
                    
                // 身份证号泄露
                case 10:
                    url = url2 + ' +(filetype:xls | filetype:pdf) (sfzh | 身份证号)';
                    break;
                    
                // TXT文件泄露
                case 11:
                    url = url2 + ' (inurl:robots.txt | filetype:txt | inurl:password.txt | inurl:users.txt | inurl:user.txt | inurl:passwd | inurl:passwords.txt | 说明.txt)';
                    break;
                    
                // 表格文件泄露
                case 12:
                    url = url2 + ' (filetype:xlsx | filetype:xls | filetype:csv)';
                    break;
                    
                // 文档文件泄露
                case 13:
                    url = url2 + ' (filetype:docx | filetype:doc | filetype:pdf)';
                    break;
                    
                // 密码文件泄露
                case 14:
                    url = url2 + ' (filetype:txt 密码 | intext:密码)';
                    break;

                // 后台管理查找Pro版
                case 15:
                    url = url2 + ' (intext:admin|管理|后台|登录|用户名|密码|验证码|系统|账号|后台管理|后台登录|管理员登陆) | (intitle:管理|后台|登录|用户名|密码|验证码|系统|账号|后台管理|后台登录|管理员登陆) | (inurl:login|admin|manage|admin_login|login_admin|system|boss|master|main|cms|wp-admin|sys|managetem|password|username|user|member)';
                    break;
                    
                // 常见文件类型泄露
                case 16:
                    url = url2 + ' (filetype:doc | filetype:docx | filetype:xml | filetype:rar | filetype:inc | filetype:mdb | filetype:txt | filetype:xls | filetype:sql | filetype:conf | filetype:pdf | filetype:xlsx | filetype:csv | filetype:ppt | filetype:pptx)';
                    break;
                // 查找管理后台路径
                case 17:
                    url = url2 + ' (inurl:admin/manager|admin|admin_index|admin_admin|index_admin|admin/index|admin/default|admin/manage|admin/login|manage_index|index_manage|superadmin|说明.txt|manager/login|manager/login.asp|manager/admin.asp|login/admin/admin.asp|houtai/admin.asp|guanli/admin.asp|denglu/admin.asp|admin_login/admin.asp|admin_login/login.asp|admin/manage/admin.asp|admin/manage/login.asp|admin/default/admin.asp|admin/default/login.asp|member/admin.asp|member/login.asp|administrator/admin.asp|administrator/login.asp)';
                    break;
                // 大佬分享01【常用的inurl语法】
                case 18:
                    url = url2 + ' (inurl:admin (filetype:txt|filetype:db|filetype:cfg)) | (inurl:mysql filetype:cfg) | (inurl:passwd filetype:txt) | (inurl:iisadmin) | (allinurl:/scripts/cart32.exe) | (allinurl:/CuteNews/show_archives.php) | (allinurl:/phpinfo.php) | (allinurl:/privmsg.php) | (inurl:auth_user_file.txt) | (inurl:orders.txt) | (inurl:"wwwroot/*.") | (inurl:adpassword.txt) | (inurl:webeditor.php) | (inurl:file_upload.php) | (inurl:gov filetype:xls "restricted") | (intitle:"index of" ftp filetype:mdb) | (allinurl:/cgi-bin/ mailto)';
                    break;
                // 大佬分享01【常用的Index of语法】
                case 19:
                    url = url2 + ' (intitle:"Index of /" (passwd|password|mail|.htaccess|secret|confidential|root|cgi-bin|credit-card|logs|config|admin)) | (intitle:"Index of /" +password.txt) | (intitle:"Index of /" +passwd)';
                    break;
            }
            window.open(url, '', 'scrollbars=yes,menubar=no,height=600,width=800,resizable=yes,toolbar=yes,menubar=no,location=no,status=no');

        }
