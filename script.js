//Main Function
//JavaScript Variable Call and User
const displayEl = document.getElementById('display');
const inputEl = document.getElementById('textInput');
const applyBtn = document.getElementById('applyBtn');
const charCount = document.getElementById('charCount')


//Section 1
//Preset Under Subdomain Finder
const presets1 = [
  { label: '*.Google', query: (site) => `site:*.${site}` },
  { label: '*.Google.*', query: (site) => `site:*.${site}*` },
  { label: '*.*.Google.*', query: (site) => `site:*.*${site}.*` },
  { label: '*.*.*.Google', query: (site) => `site:*.*.*.${site}` },
  { label: '*.*.*.*.Google', query: (site) => `site:*.*.*.*.${site}` },
  { label: '*.*.*.*.*.Google', query: (site) => `site:*.*.*.*.*.${site}` },
  { label: '*.*.*.*.*.*.*.Google', query: (site) => `site:*.*.*.*.*.*.*.${site}` }
];

//JavaScript Variable Call and User
const buttonsEl = document.getElementById('buttons1');

// create quick search buttons
presets1.forEach(({ label, query }) => {
  const btn = document.createElement('button');
  btn.className = 'small-btn';
  btn.textContent = label;
  btn.addEventListener('click', () => {
    const site = inputEl.value.trim();
    
    // If query needs the site and it's not entered
    if (query.length === 1 && !site) {
      alert("Please enter a site.");
      return;
    }
    
    const searchQuery = query.length === 1 ? query(site) : query();
    const searchUrl = `https://www.google.com/search?q=${encodeURIComponent(searchQuery)}`;
    window.open(searchUrl, '_blank');
  });
  buttonsEl.appendChild(btn);
});


//Section 2
//This is the important Part of preset (Information Disclosure)
//Preset under Information Disclosure
const presets2 = [
  { label: 'Directory Listing Vulnerabilities', query: (site) => `site:.${site} intitle:index.of` },
  { label: 'Exposed FTP', query: (site) => `site:.${site} intitle: index of inurl:ftp` },
  { label: 'Find PDFs', query: (site) => `site:${site} filetype:pdf` },
  { label: 'Exposed Configuration', query: (site) => `site:${site} ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ora | ext:ini`  }, 
  { label: 'File Upload endpoints', query: (site) => `site:${site} intext:uploadimage | intext:Upload FIle` },
  { label: 'Exposed database', query: (site) => `site:${site} ext:sql | ext:dbf | ext:mdb ` },
  { label: 'Exposed log', query: (site) => `site:${site} ext:log` },
  { label: 'Backup & Old files', query: (site) => `site:${site} ext:bkf | ext:bkp | ext:bak | ext:old | ext:backup` },
  { label: 'Publicly Exposed documents', query: (site) => `site:${site} ext:doc | ext:docx | ext:odt | ext:pdf | ext:rtf | ext:sxw | ext:psw | ext:ppt | ext:pptx | ext:pps | ext:csv` },
  { label: 'Find Emails', query: (site) => `site:${site} inurl:email | inurl:emails ext:txt | ext:xlsx | ext:doc | ext:docx` },
  { label: 'Find password 1', query: (site) => `site:${site} intext:admin.password` },
  { label: 'Find Password 2', query: (site) => `site:${site} 'admin_password' ext:txt | ext:log | ext:cfg` },
  { label: 'Find Password emails', query: (site) => `site:${site} filetype:log intext:password after:2016 intext:@gmail.com | @yahoo.com | @hotmail.com` },
  { label: 'Sensitive Documennt #1', query: (site) => `site:${site} ext:txt | ext:pdf | ext:xml | ext:xls | ext:xlsx | ext:ppt | ext:pptx | ext:doc | ext:docx intext:“confidential” | intext:“Not for Public Release” | intext:”internal use only” | intext:“do not distribute” | ext:rtf | ext:csv | ext:json | ext:zip | ext:rar | ext:log | ext:conf | ext:sql | ext:cnf | ext:ini | ext:env | ext:sh | ext:swp | ext:~ | ext:git | ext:svn | ext:htpasswd | ext:htaccess` },
  { label: 'Apache Config Files', query: (site) => `site:${site} filetype:config apache` },
  { label: 'Apache STRUTS RCE', query: (site) => `site:${site} ext:action | ext:struts | ext:do` },
  { label: 'Robots.txt', query: (site) => `site:${site}/robots.txt` },
  { label: 'phpinfo', query: (site) => `site:${site} ext:php intitle:phpinfo published` },
  { label: 'Apache Server Status', query: (site) => `site:${site}/server-status apache` },
  { label: '.htaccess Sesitive files', query: (site) => `site:${site} inurl:/phpinfo.php | inurl:.htaccess` },
  { label: 'Install/Setup Files', query: (site) => `site:*.${site} inurl:readme | inurl:license | inurl:install | inurl:setup | inurl:config` },
  { label: '3rd Party Exposure', query: (site) => `site:http://ideone.com | site:http://codebeautify.org | site:http://codeshare.io | site:http://codepen.io | site:http://repl.it | site:http://justpaste.it | site:http://pastebin.com | site:http://jsfiddle.net | site:http://trello.com | site:*.atlassian.net | site:bitbucket.org ${site}*` },
  { label: 'Finding exposed cloud service credentials', query: (site) => `site:${site}%20(intext:%22aws_access_key_id%22%20OR%20intext:%22aws_secret_access_key%22)%20(filetype:json%20OR%20filetype:yaml)` },
  { label: 'Digital Ocean Spaces', query: (site) => `site:digitaloceanspaces.com ${site}` },
  { label: 'Firebase', query: (site) => `site:firebaseio.com "${site}"` },
  { label: 's3 Bucket', query: (site) => `site:.s3.amazonaws.com ${site}` },
  { label: 'Google APIs', query: (site) => `site:googleapis.com "${site}"` },
  { label: 'Google Drive', query: (site) => `site:drive.google.com "${site}"` },
  { label: 'Azure', query: (site) => `site:dev.azure.com "${site}"` },
  { label: 'OneDrive', query: (site) => `site:onedrive.live.com "${site}"` },
  { label: 'DropBox', query: (site) => `site:dropbox.com/s "${site}"` },
  { label: 'Google Docs', query: (site) => `site:docs.google.com inurl:"/d/" "${site}"` },
  { label: 'Reverse IP Lookup', query: (site) => `Reverse_IP_Lookup${site}` },
  { label: 'Source Code-Public[WWW]', query: (site) => `SOURCE_CODE-PUBLIC[WWW]` },
  { label: 'Security Headers Scan', query: (site) => `SECURITY_HEADER${site}` },
  { label: 'Check Website OS', query: (site) => `CHECK_WEBSITE_OS${site}` },
  { label: 'Login/Admin Finder', query: (site) => `site:${site} inurl:login | inurl:admin | inurl:login | inurl:logon | inurl:sign-in | inurl:signin | inurl:signup | inurl:sign-up | inurl:dash | inurl:portal | inurl:panel | inurl:register | inurl:administrator` },
  { label: 'Finding Backdoors', query: (site) => `site:fmis.gov.kh inurl:shell | inurl:backdoor | inurl:wso | inurl:cmd | shadow | passwd | boot.ini | inurl:backdoor | intitle:Mini Shell` },
  { label: 'Employee on LinkedIn', query: (site) => `site:linkedin.com employees ${site}` },
  { label: 'Employee on facebook', query: (site) => `site:facebook.com employees ${site}` },
  { label: 'Employee on twitter', query: (site) => `site:twitter.com employees ${site}` }
];

//JavaScript Variable Call and User
const buttonsE2 = document.getElementById('buttons2');

// create quick search buttons
presets2.forEach(({ label, query }) => {
  const btn = document.createElement('button');
  btn.className = 'small-btn';
  btn.textContent = label;
  btn.addEventListener('click', () => {
    const site = inputEl.value.trim();
    
    // If query needs the site and it's not entered
    if (query.length === 1 && !site) {
      alert("Please enter a site.");
      return;
    }
    if (label === 'Security Headers Scan') {
      // Open SecurityHeaders scan in new tab
      const scanUrl = `https://securityheaders.com/?q=${encodeURIComponent(site)}&followRedirects=on`;
      window.open(scanUrl, '_blank');
    }
    else if (label === 'Check Website OS') {
      // Open Check Website OS scan in new tab
      const scanUrl = `https://iplocation.io/website-server-software/${encodeURIComponent(site)}`;
      window.open(scanUrl, '_blank'); 
    }
    else if (label === 'Reverse IP Lookup') {
      // Open Source Code Pyblic scan in new tab
      const scanUrl = `https://viewdns.info/reverseip/?host=${encodeURIComponent(site)}&t=1`;
      window.open(scanUrl, '_blank'); 
    }
    else if (label === 'Source Code-Public[WWW]') {
      // Open Reverse IP Lookup scan in new tab
      const scanUrl = `https://publicwww.com/websites/${encodeURIComponent(site)}/`;
      window.open(scanUrl, '_blank'); 
    }
    else {
      // Regular Google dork
      const searchQuery = query.length === 1 ? query(site) : query();
      const searchUrl = `https://www.google.com/search?q=${encodeURIComponent(searchQuery)}`;
      window.open(searchUrl, '_blank');
    }
  });
  buttonsE2.appendChild(btn);
});



//Section 3
//This is the important Part of preset (Information Disclosure)
//Preset Under Technology 
const presets3 = [
  { label: 'builtwith.com', query: (site) => `Builtwith${site}` },
  { label: 'webtechsurvey.com', query: (site) => `WEBTECHSURVEY${site}` },
  { label: 'web-check.xyz', query: (site) => `WEB_CHECK.XYZ${site}` },
];

//JavaScript Variable Call and User
const buttonsE3 = document.getElementById('buttons3');

// create quick search buttons
presets3.forEach(({ label, query }) => {
  const btn = document.createElement('button');
  btn.className = 'small-btn';
  btn.textContent = label;
  btn.addEventListener('click', () => {
    const site = inputEl.value.trim();
    
    // If query needs the site and it's not entered
    if (query.length === 1 && !site) {
      alert("Please enter a site.");
      return;
    }
    if (label === 'builtwith.com') {
      // Open builtwith.com scan in new tab
      const scanUrl = `https://builtwith.com/${encodeURIComponent(site)}`;
      window.open(scanUrl, '_blank');
    }
    else if (label === 'webtechsurvey.com') {
      // Open Check webtechsurvey.com scan in new tab
      const scanUrl = `https://webtechsurvey.com/website/${encodeURIComponent(site)}`;
      window.open(scanUrl, '_blank'); 
    }
    else if (label === 'w3techs.com') {
      // Open w3techs.com scan in new tab
      const scanUrl = `https://w3techs.com/sites/info/${encodeURIComponent(site)}`;
      window.open(scanUrl, '_blank'); 
    }
    else if (label === 'whatcms.org') {
      // Open whatcms.org scan in new tab
      const scanUrl = `https://whatcms.org/?s=${encodeURIComponent(site)}`;
      window.open(scanUrl, '_blank'); 
    }
  });
  buttonsE3.appendChild(btn);
});


//Section 4
//Port Scanning//
//Preset for Port Scanning
const presets4 = [
  { label: 'viewdns.info', query: (site) => `VIEWDNS.INFO${site}` },
  { label: 'dnschecker.org', query: (site) => `DNSCHECKER.ORG${site}` },
  { label: 'w3tech.com', query: (site) => `W3TECH.COM${site}` },
  { label: 'whatcms.org', query: (site) => `WHATCMS.ORG${site}` }
];

//JavaScript Variable Call and User
const buttonsE4 = document.getElementById('buttons4');

// create quick search buttons
presets4.forEach(({ label, query }) => {
  const btn = document.createElement('button');
  btn.className = 'small-btn';
  btn.textContent = label;
  btn.addEventListener('click', () => {
    const site = inputEl.value.trim();
    
    // If query needs the site and it's not entered
    if (query.length === 1 && !site) {
      alert("Please enter a site.");
      return;
    }
    if (label === 'viewdns.info') {
      // Open viewdns.info scan in new tab
      const scanUrl = `https://viewdns.info/portscan/?host=${encodeURIComponent(site)}`;
      window.open(scanUrl, '_blank');
    }
    else if (label === 'dnschecker.org') {
      // Open Check dnschecker.org scan in new tab
      const scanUrl = `https://dnschecker.org/port-scanner.php?query=${encodeURIComponent(site)}&ptype=server`;
      window.open(scanUrl, '_blank'); 
    }
    else if (label === 'web-check.xyz') {
      // Open web-check.xyz scan in new tab
      const scanUrl = `https://web-check.xyz/check/${encodeURIComponent(site)}`;
      window.open(scanUrl, '_blank'); 
    }
  });
  buttonsE4.appendChild(btn);
});


//Section 6
// Origin IP Finding
//Preset for ORIGIN IP finding
const presets5 = [
  { label: 'Shodan (Method 1)', query: (site) => `Shodan (Method 1)${site}` },
  { label: 'Shodan (Method 2)', query: (site) => `Shodan (Method 2)${site}` },
  { label: 'Search.Censys.io', query: (site) => `search.censys.io${site}` },
  { label: 'mxtoolbox.com', query: (site) => `mxtoolbox.com${site}` },
  { label: 'securitytrails.com', query: (site) => `securitytrails.com${site}` },
  { label: 'Viewdns.info', query: (site) => `VIEWDNS.INFO${site}` },
];

//JavaScript Variable Call and User
const buttonsE5 = document.getElementById('buttons5');

// create quick search buttons
presets5.forEach(({ label, query }) => {
  const btn = document.createElement('button');
  btn.className = 'small-btn';
  btn.textContent = label;
  btn.addEventListener('click', () => {
    const site = inputEl.value.trim();
    
    // If query needs the site and it's not entered
    if (query.length === 1 && !site) {
      alert("Please enter a site.");
      return;
    }
    if (label === 'Shodan (Method 1)') {
      // Open Shodan (Method 1) scan in new tab
      const scanUrl = `https://www.shodan.io/search?query=Ssl.cert.subject.CN%3A%22${encodeURIComponent(site)}%22+200`;
      window.open(scanUrl, '_blank');
    }
    else if (label === 'Shodan (Method 2)') {
      // Open Shodan (Method 2) scan in new tab
      const scanUrl = `https://www.shodan.io/search?query=ssl%3A%22${encodeURIComponent(site)}%22+200`;
      window.open(scanUrl, '_blank'); 
    }
    else if (label === 'Search.Censys.io') {
      // Open Search.Censys.io scan in new tab
      const scanUrl = `https://search.censys.io/search?resource=hosts&sort=RELEVANCE&per_page=25&virtual_hosts=EXCLUDE&q=${encodeURIComponent(site)}`;
      window.open(scanUrl, '_blank'); 
    }
    else if (label === 'mxtoolbox.com') {
      // Open mxtoolbox.com scan in new tab
      const scanUrl = `https://mxtoolbox.com/SuperTool.aspx?action=spf%3a${encodeURIComponent(site)}&run=toolpage#`;
      window.open(scanUrl, '_blank'); 
    }
    else if (label === 'securitytrails.com') {
      // Open securitytrails.com scan in new tab
      const scanUrl = `https://securitytrails.com/app/auth/login?return=/domain/${encodeURIComponent(site)}/history/a`;
      window.open(scanUrl, '_blank');
    }
    else if (label === 'viewdns.info') {
      // Open Viewdns.info scan in new tab
      const scanUrl = `https://viewdns.info/iphistory/?domain=${encodeURIComponent(site)}`;
      window.open(scanUrl, '_blank');
    }
  });
  buttonsE5.appendChild(btn);
});


//Section Preset 6
//Preset For URL Collecting
const presets6 = [
  { label: 'web.archive.org', query: (site) => `web.archive.org${site}` },
  { label: 'web.archive.org(Wildcard)', query: (site) => `web.archive.org(Wildcard)${site}` },
  { label: 'urlscan.io', query: (site) => `urlscan.io${site}` },
  { label: 'otx.alienvault.com (Hostname)', query: (site) => `otx.alienvault.com (Hostname)${site}` },
  { label: 'otx.alienvault.com (Domain)', query: (site) => `otx.alienvault.com (Domain)${site}` },
  { label: 'virustotal.com', query: (site) => `virustotal.com${site}` },
];

//JavaScript Variable Call and User
const buttonsE6 = document.getElementById('buttons6');

// create quick search buttons
presets6.forEach(({ label, query }) => {
  const btn = document.createElement('button');
  btn.className = 'small-btn';
  btn.textContent = label;
  btn.addEventListener('click', () => {
    const site = inputEl.value.trim();
    
    // If query needs the site and it's not entered
    if (query.length === 1 && !site) {
      alert("Please enter a site.");
      return;
    }
    if (label === 'web.archive.org') {
      // Open web.archive.org scan in new tab
      const scanUrl = `https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(site)}/*&output=txt&collapse=urlkey&fl=original&page=/`;
      window.open(scanUrl, '_blank');
    }
    else if (label === 'web.archive.org(Wildcard)') {
      // Open web.archive.org scan in new tab
      const scanUrl = `https://web.archive.org/cdx/search/cdx?url=*.${encodeURIComponent(site)}/*&output=txt&collapse=urlkey&fl=original&page=/`;
      window.open(scanUrl, '_blank'); 
    }
    else if (label === 'urlscan.io') {
      // Open urlscan.io scan in new tab
      const scanUrl = `https://urlscan.io/api/v1/search/?q=${encodeURIComponent(site)}&size=10000`;
      window.open(scanUrl, '_blank'); 
    }
    else if (label === 'otx.alienvault.com (Hostname)') {
      // Open otx.alienvault.com scan in new tab
      const scanUrl = `https://otx.alienvault.com/api/v1/indicators/hostname/${encodeURIComponent(site)}/url_list?limit=500&page=1`;
      window.open(scanUrl, '_blank'); 
    }
    else if (label === 'otx.alienvault.com (Domain)') {
      // Open otx.alienvault.com scan in new tab
      const scanUrl = `https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(site)}/url_list?limit=500&page=1`;
      window.open(scanUrl, '_blank');
    }
    else if (label === 'virustotal.com') {
      // Open virustotal.com scan in new tab
      const scanUrl = `https://www.virustotal.com/vtapi/v2/domain/report?apikey=3b3467a2b03a10b2bdc43c7fee43122e70628e65becd7fbae2d95d38f26bd7f9&domain=${encodeURIComponent(site)}`;
      window.open(scanUrl, '_blank');
    }
  });
  buttonsE6.appendChild(btn);
});

//Section Preset 7
//Preset for URL parameter
const presets7 = [
  { label: 'SQLi Parameter', query: (site) => `site:${site} inurl:cat= | inurl:search= | inurl:action= | inurl:module= | inurl:rep= | inurl:review= | inurl:rep= | inurl:rep= | inurl:rep= | inurl:rep= | inurl:rep= | inurl:total= | inurl:selectID= | inurl:page= | inurl:search= | inurl:recherche= | inurl:term= | inurl:misc= | inurl:idProduct= | inurl:num= | inurl:idCategory= | inurl:no= | inurl:table= | inurl:bbs= | inurl:bookPageNo= | inurl:proj_nr= | inurl:card= | inurl:category= | inurl:LAN= | inurl:cid= | inurl:class= | inurl:column= | inurl:p= | inurl:mode= | inurl:date= | inurl:cPath= | inurl:delete= | inurl:dir= | inurl:chnum= | inurl:code= | inurl:email= | inurl:T****= | inurl:fetch= | inurl:file= | inurl:field= | inurl:first name= | inurl:form= | inurl:from= | inurl:filter= | inurl:pr= | inurl:gubun=` },
  { label: 'SQLi Parameter (68)', query: (site) => `site:${site} inurl:doc= | inurl:code= | inurl:data= | inurl:id= | inurl:view= | inurl:i= | inurl:modus= | inurl:section= | inurl:site= | inurl:url= | inurl:w= | inurl:item= | inurl:join= | inurl:board= | inurl:keyword= | inurl:lang= | inurl:last name= | inurl:login= | inurl:ps_db= | inurl:main= | inurl:menu= | inurl:typeboard= | inurl:name= | inurl:nav= | inurl:t= | inurl:news= | inurl:number= | inurl:show= | inurl:order= | inurl:orm= | inurl:ref= | inurl:modul= | inurl:params= | inurl:pass= | inurl:password= | inurl:PageID= | inurl:pid= | inurl:process= | inurl:shop= | inurl:q= | inurl:query= | inurl:region= | inurl:register= | inurl:report= | inurl:reset password= | inurl:reset= | inurl:results= | inurl:role= | inurl:row= | inurl:search= | inurl:sel= | inurl:select= | inurl:sleep= | inurl:sort= | inurl:string= | inurl:table= | inurl:thread= | inurl:time= | inurl:title= | inurl:topic= | inurl:type= | inurl:update= | inurl:url= | inurl:user= | inurl:username= | inurl:users= | inurl:view= | inurl:where=` },
  { label: 'Error SQLi (71)', query: (site) => `site:${site} intext:Syntax error | intext:Fatal error | intext:MariaDB | intext:corresponds | intext:Database Error | intext:syntax | intext:/usr/www | intext:public_html | intext:database error | intext:on line | intext:RuntimeException | intext:mysql_ | intext:MySQL | intext:PSQLException | intext:at line | intext:You have an error in your SQL syntax | intext:mysql_query() | intext:pg_connect() | intext:SQLiteException | intext:ORA- | intext:invalid input syntax for type | intext:unterminated quoted string | intext:PostgreSQL query failed: | intext:unrecognized token: | intext:binding parameter | intext:undeclared variable: | intext:SQLSTATE | intext:constraint failed | intext:ORA-00936: missing expression | intext:ORA-06512: | intext:PLS- | intext:SP2- | intext:dynamic SQL error | intext:SQL command not properly ended | intext:T-SQL Error | intext:Msg | intext:Level | intext:Unclosed quotation mark after the character string | intext:quoted string not properly terminated | intext:Incorrect syntax near | intext:An expression of non-boolean type specified in a context where a condition is expected | intext:Conversion failed when converting | intext:Unclosed quotation mark before the character string | intext:SQL Server | intext:OLE DB | intext:Unknown column | intext:Access violation | intext:No such host is known | intext:server error | intext:syntax error at or near | intext:column does not exist | intext:could not prepare statement | intext:no such table: | intext:near | intext:unknown error | intext:unexpected end of statement | intext:ambiguous column name | intext:database is locked | intext:permission denied | intext:attempt to write a readonly database | intext:out of memory | intext:disk I/O error | intext:cannot attach the file | intext:operation is not allowed in this state | intext:data type mismatch | intext:cannot open database | intext:table or view does not exist | intext:index already exists | intext:index not found | intext:division by zero | intext:value too large for column` },
  { label: 'Error SQLi (16)', query: (site) => `site:${site} intext:deadlock detected | intext:invalid operator | intext:sequence does not exist | intext:duplicate key value violates unique constraint | intext:string data, right truncated | intext:insufficient privileges | intext:missing keyword | intext:too many connections | intext:configuration limit exceeded | intext:network error while attempting to read from the file | intext:cannot rollback - no transaction is active | intext:feature not supported | intext:system error | intext:object not in prerequisite state | intext:login failed for user | intext:remote server is not known`  }, 
  { label: 'Post Parameter', query: (site) => `site:${site} inurl:search.php | inurl:process.php | inurl:admin-post.php` },
  { label: 'Open Redirect (41)', query: (site) => `site:${site} inurl:redir= | inurl:url= | inurl:redirect= | inurl:return= | inurl:src=http | inurl:r=http | inurl:goto= | inurl:Lmge_url= | inurl:Open= | inurl:cgi-bin/redirect.cgi | inurl:checkout= | inurl:data= | inurl:dir= | inurl:domain= | inurl:feed= | inurl:file= | inurl:file_name= | inurl:file_url= | inurl:folder= | inurl:forward= | inurl:from_uri= | inurl:goto= | inurl:host= | inurl:html= | inurl:img_url= | inurl:load_file= | inurl:load_url= | inurl:login?to= | inurl:login_url= | inurl:logout= | inurl:navigation= | inurl:next_page= | inurl:page= | inurl:page_url= | inurl:redirect_to= | inurl:redirect_uri= | inurl:reference= | inurl:return_url= | inurl:rt= | inurl:ret= | inurl:r2= ` },
  { label: 'Open Redirect (18)', query: (site) => `site:${site} inurl:show= | inurl:site= | inurl:uri= | inurl:val= | inurl:next= | inurl:url= | inurl:target= | inurl:rurl= | inurl:dest= | inurl:redir= | inurl:out= | inurl:image_url= | inurl:returnTo= | inurl:checkout_url= | inurl:continue= | inurl:=http | inurl:?next= | inurl:nexrurI=` },
  { label: 'SSRF Params (24)', query: (site) => `site:${site} inurl:redir | inurl:url= | inurl:redirect= | inurl:return= | inurl:dest= | inurl:uri= | inurl:path= | inurl:continue= | inurl:window= | inurl:next= | inurl:data= | inurl:reference= | inurl:site= | inurl:html= | inurl:val= | inurl:validate= | inurl:domain= | inurl:callback= | inurl:feed= | inurl:host= | inurl:port= | inurl:to= | inurl:out= | inurl:view= | inurl:dir=` },
  { label: 'RCE Params (23)', query: (site) => `site:${site} inurl:cmd= | inurl:exec= | inurl:command= | inurl:execute= | inurl:ping= | inurl:query= | inurl:jump= | inurl:code= | inurl:reg= | inurl:do= | inurl:func= | inurl:arg= | inurl:option= | inurl:load= | inurl:process= | inurl:step= | inurl:read= | inurl:feature= | inurl:exe= | inurl:module= | inurl:payload= | inurl:run= | inurl:print=` },
  { label: 'XSS Params (27)', query: (site) => `site:${site} inurl:q= | inurl:s= | inurl:username= | inurl:search= | inurl:id= | inurl:lang= | inurl:keyword= | inurl:query= | inurl:page= | inurl:year= | inurl:view= | inurl:email= | inurl:type= | inurl:name= | inurl:p= | inurl:month= | inurl:image= | inurl:list_type= | inurl:url= | inurl:terms= | inurl:categoryid= | inurl:key= | inurl:l= | inurl:begindate= | inurl:enddate= | inurl:inviteby= | inurl:utm_source=` },
  { label: 'XSS Params (22)', query: (site) => `site:${site} inurl:errmsg= | inurl:option= | inurl:Itemid= | inurl:faq= | inurl:key= | inurl:news_type= | inurl:sid= | inurl:msg= | inurl:msg1= | inurl:session= | inurl:search_keywords= | inurl:sfunction= | inurl:order_direction= | inurl:author= | inurl:feedback= | inurl:max= | inurl:searchstring= | inurl:tag= | inurl:txt= | inurl:vote= | inurl:catid= | inurl:redirectUrl=` },
  { label: 'IDOR Params (12)', query: (site) => `site:${site} inurl:user= | inurl:id= | inurl:email= | inurl:account= | inurl:number= | inurl:order= | inurl:no= | inurl:doc= | inurl:key= | inurl:group= | inurl:profile= | inurl:edit= | inurl:report=` },
  { label: 'LFI Params (24)', query: (site) => `site:${site} inurl:cat= | inurl:dir= | inurl:action= | inurl:board= | inurl:date= | inurl:file= | inurl:download= | inurl:path= | inurl:folder= | inurl:prefix= | inurl:include= | inurl:page= | inurl:inc= | inurl:locate= | inurl:show= | inurl:doc= | inurl:site= | inurl:type= | inurl:view= | inurl:content= | inurl:document= | inurl:layout= | inurl:mod= | inurl:conf=` },
  { label: 'Information Disclosure Ext (58)', query: (site) => `site:${site} ext:xls | ext:xml | ext:xlsx | ext:json | ext:pdf | ext:sql | ext:doc | ext:docx | ext:pptx | ext:txt | ext:zip | ext:tar.gz | ext:tgz | ext:bak | ext:7z | ext:rar | ext:log | ext:cache | ext:secret | ext:db | ext:backup | ext:yml | ext:gz | ext:config | ext:csv | ext:yaml | ext:md | ext:md5 | ext:tar | ext:xz | ext:7zip | ext:p12 | ext:pem | ext:key | ext:crt | ext:csr | ext:sh | ext:pl | ext:py | ext:java | ext:class | ext:jar | ext:war | ext:ear | ext:sqlitedb | ext:sqlite3 | ext:dbf | ext:db3 | ext:accdb | ext:mdb | ext:sqlcipher | ext:gitignore | ext:env | ext:ini | ext:conf | ext:properties | ext:plist | ext:cfg` },
];

//JavaScript Variable Call and User
const buttonsE7 = document.getElementById('buttons7');

// create quick search buttons
presets7.forEach(({ label, query }) => {
  const btn = document.createElement('button');
  btn.className = 'small-btn';
  btn.textContent = label;
  btn.addEventListener('click', () => {
    const site = inputEl.value.trim();
    
    // If query needs the site and it's not entered
    if (query.length === 1 && !site) {
      alert("Please enter a site.");
      return;
    }
    
    const searchQuery = query.length === 1 ? query(site) : query();
    const searchUrl = `https://www.google.com/search?q=${encodeURIComponent(searchQuery)}`;
    window.open(searchUrl, '_blank');
  });
  buttonsE7.appendChild(btn);
});

//Section 5
//Box for copy Text when we input
function appendToDisplay(text) {
  const seg = document.createElement('div');
  seg.className = 'segment';
  seg.style.padding = '6px 8px';
  seg.style.marginBottom = '6px';
  seg.style.borderRadius = '8px';
  seg.style.background = 'linear-gradient(90deg, rgba(255,255,255,0.012), transparent)';
  seg.style.cursor = 'pointer';
  seg.textContent = text;
  seg.addEventListener('click', async () => {
    await copyText(seg.textContent);
    flash(seg, 'Copied');
  });
  displayEl.appendChild(seg);
  updateCharCount();
}
//Copy text 
async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    ta.remove();
  }
}
//Count char Update
function updateCharCount() {
  const txt = Array.from(displayEl.querySelectorAll('.segment'))
    .map(s => s.textContent).join('\n');
  charCount.textContent = txt.length;
}

function flash(el, msg) {
  const original = el.textContent;
  el.textContent = msg;
  setTimeout(() => { el.textContent = original; }, 900);
}


//Section 6
//Tool and CMD for testing
function initCommandGenerator() {
  const inputEl = document.getElementById('textInput');
  const container = document.getElementById('commandsContainer');

  const commandFields = [
    {
      id: 'commandField0',
      template: domain => 
        `cat ${domain} | rush -j20 'if curl -Is "{}" | head -1 | grep -q "HTTP"; then echo "Running Sqlmap on '{}'"; sqlmap -u "{}" --batch --random-agent --dbs; fi'`
    },
    {
      id: 'commandField1',
      template: domain => 
        `nmap -p 80,443 ${domain}`
    },
    {
      id: 'cmd2',
      template: domain => 
        `ffuf -w wordlist.txt -u http://${domain}/FUZZ`
    },
    {
      id: 'dbg5',
      template: domain => 
        `gdb -p $(pidof someprocess)`
    },
  ];

  // Create inputs dynamically and add click copy listeners
  commandFields.forEach(({id}) => {
    const input = document.createElement('input');
    input.type = 'text';
    input.id = id;
    input.readOnly = true;
    input.className = 'btn-ghost';
    input.title = 'Click to copy command';
    input.style.width = '100%';
    input.style.marginBottom = '6px';

    input.addEventListener('click', e => {
      e.target.select();
      if (navigator.clipboard) {
        navigator.clipboard.writeText(e.target.value).then(() => {
          alert('Copied command!');
        }).catch(() => {
          document.execCommand('copy');
          alert('Copied command!');
        });
      } else {
        document.execCommand('copy');
        alert('Copied command!');
      }
    });

    container.appendChild(input);
  });

  // Update all command fields
  function updateCommandFields() {
    const domain = inputEl.value.trim() || "domaintarget.com";
    commandFields.forEach(({id, template}) => {
      const field = document.getElementById(id);
      if (field) {
        field.value = template(domain);
      }
    });
  }

  // Listen for typing in main input
  inputEl.addEventListener('input', updateCommandFields);

  // Initialize on page load
  updateCommandFields();
}

// Run after DOM is loaded
document.addEventListener('DOMContentLoaded', initCommandGenerator);

applyBtn.addEventListener('click', () => {
  const v = inputEl.value.trim();
  if (!v) return;
  appendToDisplay(v + '\n');
  inputEl.value = '';
});

document.querySelectorAll('.top-name').forEach(el => {
  el.addEventListener('click', () => {
    appendToDisplay(`=== ${el.dataset.name} ===\n`);
  });
});

//appendToDisplay('Welcome — enter a site, then click a button to search in Google.\n');
updateCharCount();


//Section 7 (Security Implementation)
// Disable Ctrl+A / Ctrl+C
document.addEventListener('keydown', function(e) {
  const ctrlOrCmd = e.ctrlKey || e.metaKey;
  if (ctrlOrCmd) {
    if (e.key.toLowerCase() === 'a') {
      e.preventDefault();
      alert("Select All is disabled on this page.");
    }
    if (e.key.toLowerCase() === 'c') {
      e.preventDefault();
      alert("Copy is disabled on this page.");
    }
  }
});

// Disable right-click
document.addEventListener('contextmenu', e => e.preventDefault());

// Block F12, Ctrl+Shift+I/J, Ctrl+U
document.addEventListener('keydown', function(e) {
  if (e.key === 'F12') e.preventDefault();
  if (e.ctrlKey && e.shiftKey && e.key.toLowerCase() === 'i') e.preventDefault();
  if (e.ctrlKey && e.shiftKey && e.key.toLowerCase() === 'j') e.preventDefault();
  if (e.ctrlKey && e.key.toLowerCase() === 'u') e.preventDefault();
});
