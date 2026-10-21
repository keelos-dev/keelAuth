// The page's texts in Chinese and English (keel's i18n.js approach): the language follows the
// browser unless the user picked one (kept in localStorage). t("key", a, b) puts a, b in for
// {0}, {1}; tr("key", fallback, a) is t with a fallback for keys this page does not know.

const dict = {
  en: {
    "lang.name": "English",
    "top.logout": "Log out", "top.menu": "Menu", "top.lang": "Language", "top.theme": "Theme",
    "theme.auto": "Auto", "theme.light": "Light", "theme.dark": "Dark",
    "scope.admin": "administrator", "scope.user": "user",
    "loading": "Loading…", "dlg.ok": "OK", "dlg.cancel": "Cancel", "dlg.done": "Done",
    "save": "Save", "edit": "Edit", "delete": "Delete", "copy": "Copy", "copied": "Copied", "show": "Show",
    "shown.once": "Shown only now: keelAuth does not show it again.",
    "login.to": "Log in to keelAuth", "login.user": "User name", "login.password": "Password", "login.button": "Log in",
    "login.hint": "Your keelAuth account. Administrators (group keelauth-admins) manage keelAuth here; everybody else can change their own password.",
    "login.noadmin": "keelAuth has no administrator yet: make one in keelOS's Accounts tab, or with keelauthd admin NAME on the VM's console.",
    "srv.bad_login": "Wrong user name or password.", "srv.disabled": "This account is disabled.", "srv.too_many": "Too many failed logins. Wait a few minutes.",
    "srv.csrf": "The page is out of date: reload it.", "srv.not_admin": "Only members of keelauth-admins may do this.", "srv.login": "Log in first.",
    "srv.bad_password": "The current password is wrong.", "srv.must_change": "Change your password first.", "srv.weak_password": "keelAuth does not accept this password",
    "nav.overview": "Overview", "nav.users": "Users", "nav.groups": "Groups", "nav.access": "Access", "nav.backup": "Backup", "nav.settings": "Settings",
    "ov.version": "Version", "ov.addresses": "Addresses", "ov.uptime": "keelauthd running for", "ov.lastbackup": "Last backup", "ov.never": "never",
    "ov.alerts": "Needs attention", "ov.services": "Services", "ov.running": "running", "ov.down": "not running", "ov.registered": "connected", "ov.standalone": "not managed by keel (no seed disk): standalone",
    "ov.notyet": "not connected yet", "ov.accounts": "Accounts", "ov.ways": "Ways in",
    "alert.engine": "Kanidm (the account engine) is not ready: {0}.", "alert.service_down": "{0} is not running.",
    "alert.radius_behind": "FreeRADIUS has not taken the latest changes yet.",
    "alert.missing_nt": "No Wi-Fi or share password yet for {0}: set their password again here once.",
    "alert.no_admin": "Nobody is an administrator of keelAuth (group keelauth-admins).", "alert.no_backup": "No backup yet.",
    "alert.old_backup": "The last backup is more than two days old.",
    "users.new": "New user", "users.add": "Add user", "users.name": "User name", "users.display": "Full name", "users.mail": "Mail",
    "users.groups": "Groups", "users.password": "Password", "users.setat": "Password set",
    "users.namehint": "Lower-case letters, digits, - and _, a letter first: what people type to log in (e.g. anna).",
    "users.autopw": "Let keelAuth make the password (shown once)", "users.mustchange": "Must choose their own password at the next login",
    "users.edit": "Edit {0}", "users.reset": "New password", "users.resettitle": "New password for {0}",
    "users.resetnote": "The old password stops working everywhere at once: LDAP, SSO, Wi-Fi, shares.",
    "users.disable": "Disable", "users.enable": "Enable", "users.disabled": "disabled", "users.admin": "admin", "users.mustshort": "must change",
    "users.nont": "no Wi-Fi/share password", "users.nonttip": "Its password was not set through keelAuth: set it again here once for Wi-Fi and shares.",
    "users.disableq": "Disable {0}? Logins stop everywhere (LDAP, SSO, Wi-Fi, shares) until it is enabled again.",
    "users.deleteq": "Delete {0} for good? Its account, groups and password are gone; files it owns on shares stay.",
    "users.none": "No users yet.", "users.pwset": "Password set", "users.pwfor": "Password for {0}",
    "users.pwonce": "Give this password to the person (shown only now). They log in at this page to choose their own.",
    "users.note": "One account everywhere: the same name and password for LDAP, SSO, Wi-Fi (RADIUS) and keelNAS shares. Passwords are set only here.",
    "pw.title": "Change your password", "pw.own": "Change my password", "pw.old": "Current password", "pw.new": "New password", "pw.again": "New password again",
    "pw.change": "Change password", "pw.changed": "Password changed", "pw.mismatch": "The two new passwords differ.",
    "pw.must": "An administrator set your password: choose your own now.",
    "pw.useronly": "Only administrators manage keelAuth; here you can change your own password.",
    "pw.rules": "At least 10 characters and not easy to guess (no common words or simple patterns). It is the password for LDAP, SSO, Wi-Fi and shares alike.",
    "groups.group": "group", "groups.new": "New group", "groups.add": "Add group", "groups.name": "Group name", "groups.desc": "Description", "groups.members": "Members",
    "groups.edit": "Edit {0}", "groups.builtin": "built in", "groups.admindesc": "keelAuth's administrators",
    "groups.adminnote": "Members of keelauth-admins manage keelAuth. The last one cannot be removed.",
    "groups.deleteq": "Delete group {0}? Its members stay; what the group allowed (SSO applications, shares) no longer applies.",
    "groups.nousers": "No users to add yet.", "groups.note": "Groups decide who may log in to an SSO application, who may use Wi-Fi and, with keelNAS, who may open a share.",
    "acc.ldap": "LDAP", "acc.sso": "SSO (OIDC)", "acc.radius": "RADIUS", "acc.radiusclients": "RADIUS clients",
    "acc.fill": "What to fill in on the other side", "acc.ca": "Download the CA certificate",
    "ldap.for": "For devices and programs that look users up or check passwords over LDAP: printers and copiers (address book, login), Linux machines, mail (Dovecot), GitLab, Redmine and other self-hosted applications. Read-only.",
    "ldap.server": "Server", "ldap.port": "Port", "ldap.security": "Security", "ldap.ldaps": "LDAPS (SSL/TLS from the start; not StartTLS)",
    "ldap.binddn": "Bind DN (user)", "ldap.bindpw": "Bind password", "ldap.userfilter": "User filter", "ldap.loginattr": "Login attribute (uid)",
    "ldap.attrs": "Other attributes", "ldap.groupfilter": "Group filter",
    "ldap.reset": "New bind password", "ldap.resetq": "Make a new bind password? Every device that uses the old one must be changed.", "ldap.reset.done": "New bind password made",
    "ldap.examples": "Configuration examples", "ldap.exfor": "Configuration for {0}", "ldap.exfile": "File:", "ldap.exholder": "{0} stands for the device account's password (shown when it is made or gets a new one).", "ldap.devnew": "New device account", "ldap.devadd": "Make", "ldap.devfor": "One account per printer, Linux machine or application: it can read users, groups and mail addresses, nothing else, and is revoked on its own. Its password is a long token, shown once.", "ldap.devname": "Name", "ldap.devdesc": "What it is", "ldap.devdescex": "Copier, 2nd floor", "ldap.devmade": "Device account {0}", "ldap.devonce": "Shown only now: enter it into the device. keelAuth does not show it again (“New password” makes another).", "ldap.exwith": "Examples with this password", "ldap.devnewpwq": "Make a new password for {0}? The old one stops working at once.", "ldap.devdelq": "Delete device account {0}? The device can no longer read keelAuth's users.", "ldap.devices": "Device accounts", "ldap.devnone": "No device accounts yet: make one for each printer, Linux machine or application.", "ldap.devpwat": "Password made", "ldap.devmissing": "keelAuth knows this account, Kanidm not (an older backup was restored): make a new password to make it again.", "ldap.devmissingb": "missing", "ldap.devnewpw": "New password", "ldap.devpw": "the device account's password (shown when it is made)", "ldap.mailattr": "Mail attribute", "ldap.nameattr": "Name attribute", "ldap.member": "members:", "ldap.shared": "Shared read-only account (short password, no mail addresses)", "ldap.sharedfor": "For a device whose password field is too short for a device account's token: it can look users up and check their passwords, but Kanidm gives password logins no mail addresses. All devices share it.", "ldap.note": "Anonymous reading is off. Applications that check a person's password bind as that person (name=<user>,<Base DN>) after finding them with the device account. The certificate names {0}: devices that check it need {0} in the office DNS (or their hosts file) and keelAuth's CA.", "rad.fillap": "On the access point (or VPN gateway)", "rad.acct": "Accounting", "rad.acctv": "off (not used)", "rad.fillclient": "On phones and laptops (only when they ask)", "rad.inner": "Phase 2 (inner)", "rad.ca": "CA certificate", "rad.domain": "Domain (server name to check)", "rad.identity": "Identity", "rad.anon": "Anonymous identity", "rad.anonv": "empty, or anonymous", "rad.note": "Most phones ask once whether to trust the server: they should see the name {0}. Android 11 and later wants a CA and a domain: install the CA (.cer), choose it, domain {0}. iPhone and Mac: the Apple profile, or accept the certificate on the first login. Windows asks once; managed laptops set “Connect to these servers: {0}” and the CA as trusted root.", "rad.fp": "CA fingerprints: SHA-256 {0} · SHA-1 {1}", "cert.warn": "Taken, note: {0}", "cert.office": "Use the office's certificate…", "cert.replace": "Replace the office's certificate…", "cert.use": "Use it", "cert.officefor": "A certificate of the office's own CA (or a public one) for {0}, with its private key. LDAPS, single sign-on, this page and Wi-Fi (PEAP) switch to it; keelAuth's own certificates are kept, “Back to keelAuth's own” returns to them.", "cert.certfile": "Certificate (PEM)", "cert.certhint": "The certificate for the domain, then its intermediate certificates and the root (one file or pasted one after the other).", "cert.keyfile": "Private key (PEM)", "cert.keyhint": "Unencrypted (PKCS#8, RSA or EC). Empty when it is in the certificate file.", "cert.officenote": "keelAuth checks: the key belongs to the certificate, it names the domain, it is valid now, it is for TLS servers, an RSA key has at least 2048 bits and the chain leads to a root. Kanidm and FreeRADIUS restart (a few seconds); if they refuse it, keelAuth stays on what it had.", "cert.days": "{0} days left", "cert.back": "Back to keelAuth's own", "cert.backq": "Go back to keelAuth's own certificates? Devices that trust only the office's CA must then trust keelAuth's CA.", "cert.backdone": "keelAuth's own certificates are in use", "cert.usedone": "The office's certificate is in use", "cert.inuse": "In use", "cert.inuseoffice": "the office's certificate (uploaded {0})", "cert.inuseown": "keelAuth's own (its CA)", "cert.anchor": "CA devices trust", "cert.pem": "PEM (.crt)", "cert.der": "DER (.cer: Windows, Android)", "cert.apple": "Apple profile", "cert.public": "Devices can also fetch it without a login: https://{0}/ca/keelauth-ca.crt (.cer, .mobileconfig).", "cert.server": "LDAPS, single sign-on, this page", "cert.radius": "Wi-Fi (PEAP)", "cert.ownca": "keelAuth's own CA", "cert.notused": "kept, not in use", "cert.forOffice": "keelAuth uses the office's own certificate. keelAuth's own CA and certificates are kept (and renewed) for going back.",
    "sso.for": "Single sign-on for web applications (OpenID Connect): people log in once at keelAuth's page and are in. Register each application here, then enter what it gets into the application's OIDC settings.",
    "sso.new": "New application", "sso.add": "Register", "sso.name": "Name", "sso.namehint": "Short, lower-case: it becomes the client ID (e.g. gitlab).",
    "sso.display": "Shown as", "sso.redirects": "Redirect URLs", "sso.redirectshint": "The application's callback addresses, one per line (in its OIDC settings, e.g. https://gitlab.office.lan/users/auth/openid_connect/callback).",
    "sso.landing": "Application address (optional)", "sso.who": "Who may log in", "sso.everyone": "everybody",
    "sso.pkce": "Require PKCE (S256): turn off only for old applications that cannot do it", "sso.nopkce": "no PKCE",
    "sso.edit": "Edit {0}", "sso.secret": "Secret", "sso.newsecret": "New secret", "sso.resetq": "Make a new client secret for {0}? The application stops logging people in until it has the new one.",
    "sso.deleteq": "Remove {0}? Its logins through keelAuth stop.", "sso.none": "No applications yet.",
    "sso.issuer": "Issuer", "sso.discovery": "Discovery URL", "sso.clientid": "the application's name in the list above", "sso.clientsecret": "shown when it is registered (Secret button)",
    "sso.scopes": "Scopes", "sso.auth": "Client authentication", "sso.userclaim": "User name claim",
    "sso.note": "The login page is keelAuth's own (Kanidm, https://<domain>:8443): the browsers must reach keelAuth under its domain name (an entry in the office DNS, or the hosts file) and trust keelAuth's certificate (CA download on the LDAP tab); Kanidm's login works only under that name. keelOS's own login needs neither: keel shows this page on its own address.",
    "sso.noteip": "This keelAuth uses its fixed LAN address as the origin (IP mode): no DNS entry is needed, the applications and browsers only have to trust keelAuth's CA. Passkeys are not available in this mode.",
    "sso.short": "User name without @domain (alice, not alice@domain): most applications take it as the login name", "sso.connect": "Connect", "sso.connect1": "{0}: enter these in the application", "sso.redirectsset": "registered here (Edit); must match the application's exactly", "sso.groupclaim": "Groups claim", "sso.claimex": "e.g. {0}", "sso.rolesfor": "{0} ({1}) gives these keelAuth groups rights:", "sso.rolegroup": "keelAuth group", "sso.rolemeans": "In {0}", "sso.makegroup": "Make the group", "sso.groupok": "exists", "sso.groupmade": "Group {0} made: add its members on the Groups page", "sso.roleshint": "Put people into these groups (Groups page). Someone in none of them is refused there; changes reach it within 15 minutes.",
    "sso.for1": "{0}: enter these in the application", "sso.secretnote": "Keep the secret in the application's settings only.",
    "rad.for": "For the office Wi-Fi with a personal login (WPA2/WPA3-Enterprise) and VPN gateways: each person uses their own keelAuth name and password, nobody shares a Wi-Fi password, and a disabled user is off the Wi-Fi at once.",
    "rad.new": "New client", "rad.add": "Add client", "rad.name": "Name", "rad.address": "Address", "rad.secret": "Shared secret",
    "rad.addresshint": "The access point's (or VPN gateway's) IP address, or a network for several (192.168.1.0/24).",
    "rad.secrethint": "Empty: keelAuth makes one.", "rad.secretkeep": "Empty: keep the current one.",
    "rad.edit": "Edit {0}", "rad.deleteq": "Remove client {0}? It can no longer ask keelAuth.", "rad.none": "No clients yet: add each access point.",
    "rad.who": "Who may use it:", "rad.everyone": "every user", "rad.users": "{0} users can log in",
    "rad.missing": "Without a Wi-Fi password until their password is set again here: {0}",
    "rad.server": "RADIUS server", "rad.port": "Port", "rad.secretper": "per client, see the list above", "rad.security": "Security", "rad.eap": "EAP method",
    "rad.login": "Login on the phone/laptop", "rad.loginv": "the person's keelAuth user name and password",
    "rad.for1": "{0}: enter these on the access point", "rad.shownote": "The secret stays visible in the list (Show).",
    "bk.now": "Back up now", "bk.keep": "Keep", "bk.keepn": "Backups to keep", "bk.done": "Backup made", "bk.none": "No backups yet.",
    "bk.time": "Time", "bk.size": "Size", "bk.file": "File", "bk.restore": "Restore",
    "bk.restoreq": "Restore the backup of {0}? Users, groups, passwords and applications go back to that time; whatever changed since is lost. keelAuth's login (Kanidm) stops for a moment.",
    "bk.restored": "Restored", "bk.note": "keelAuth backs up once a day by itself and keeps the newest {0} ({1}). Download one to keep it elsewhere; its Wi-Fi and share password hashes stay sealed: another keelAuth needs this one's recovery key to restore it.", "bk.download": "Download",
    "set.ai": "AI management", "set.sync": "keelNAS", "set.cert": "Certificates", "set.general": "General",
    "lock.title": "keelAuth is locked", "lock.why": "The key that protects the Wi-Fi and share password hashes cannot be opened here (the data disk came from another keelAuth, or this keelAuth has a new system disk). Nothing works until it is given.",
    "lock.input": "Recovery key (KAR1-…) or recovery passphrase", "lock.button": "Unlock", "lock.hint": "keelOS: Accounts → Recovery key shows the recovery key of a keelAuth it manages; a standalone keelAuth uses the passphrase set under Settings → General.",
    "srv.locked": "keelAuth is locked: give its recovery key or passphrase first.", "srv.need_recovery_key": "This backup was made by another keelAuth: give its recovery key (keelOS: Accounts → Recovery key) or its recovery passphrase.",
    "srv.bad_key": "This recovery key or passphrase does not fit.",
    "gen.tz": "Time zone", "gen.tzkeel": "{0} (keelOS's setting)", "gen.tzfor": "Times on this page are shown in this zone (where the office is), not in the browser's.",
    "gen.tztitle": "Time zone", "gen.mk": "Password hash protection", "gen.mkkeel": "wrapped with keelOS's key", "gen.mkpass": "wrapped with the recovery passphrase (set {0})",
    "gen.mknone": "not protected: set a recovery passphrase", "gen.setpass": "Set recovery passphrase", "gen.changepass": "Change recovery passphrase",
    "gen.passfor": "The Wi-Fi and share password hashes are encrypted with a key that is kept wrapped with this passphrase: a backup alone, or the data disk alone, does not give them away. You need it to restore a backup elsewhere or after a new system disk. Keep it somewhere safe: nobody can recover it.",
    "gen.pass": "Passphrase (at least 12 characters)", "gen.pass2": "Again", "gen.passdiff": "The two passphrases differ.", "gen.passset": "Recovery passphrase set",
    "gen.mkkeelnote": "keelOS keeps the key: its Accounts tab shows the recovery key for restoring a backup on another host.",
    "bk.upload": "Upload backup…", "bk.uploaded": "Uploaded: {0}", "bk.keytitle": "Restore {0}", "bk.keyfor": "This backup was made by another keelAuth. Its recovery key (keelOS: Accounts → Recovery key on the host it came from) or its recovery passphrase opens it.",
    "ov.mk": "Password hashes",
    "alert.master_key_unprotected": "Set a recovery passphrase (Settings → General): until then the key that protects the Wi-Fi and share password hashes is in clear on the data disk and in every backup.",
    "alert.locked": "keelAuth is locked: give its recovery key or passphrase.",
    "ai.title": "AI management (MCP)", "ai.new": "New token", "ai.for": "An assistant (Claude and others that speak MCP) can manage keelAuth: list and add users, reset passwords, groups, SSO applications, RADIUS clients, backups. Give it a token of its own; revoke it here.",
    "ai.connect": "Connecting", "ai.note": "keel-mcp comes with keelOS; the fingerprint checks keelAuth's certificate: {0}", "ai.made": "{0}", "ai.token": "Token", "ai.command": "Command",
    "tok.make": "Make", "tok.name": "Name", "tok.namehint": "What or who it is for (e.g. \"Claude on Anna's laptop\").", "tok.none": "None yet.",
    "tok.created": "Made", "tok.used": "Last used", "tok.revoke": "Revoke", "tok.revokeq": "Revoke {0}? Whatever uses it stops at once.",
    "sync.title": "keelNAS sync keys", "sync.new": "New key", "sync.for": "A keelNAS that takes its users from keelAuth reads them (with the Windows share password hashes) with a key of its own.", "sync.key": "Key",
    "cert.title": "Certificates", "cert.for": "keelAuth has its own certificate authority: LDAPS, the SSO login page and this page use a certificate it made. Install the CA certificate on devices and browsers once and they trust all three.",
    "cert.domain": "Domain", "cert.origin": "SSO address", "cert.fp": "This page's certificate (SHA-256)",
    "cert.note": "The domain is set when keelAuth is made and cannot change later (it is in every SSO application's issuer). Devices must find it in DNS, or use the addresses.",
  },
  zh: {
    "lang.name": "中文",
    "top.logout": "退出", "top.menu": "菜单", "top.lang": "语言", "top.theme": "外观",
    "theme.auto": "自动", "theme.light": "浅色", "theme.dark": "深色",
    "scope.admin": "管理员", "scope.user": "用户",
    "loading": "加载中…", "dlg.ok": "确定", "dlg.cancel": "取消", "dlg.done": "完成",
    "save": "保存", "edit": "修改", "delete": "删除", "copy": "复制", "copied": "已复制", "show": "显示",
    "shown.once": "只显示这一次：keelAuth 以后不再显示。",
    "login.to": "登录 keelAuth", "login.user": "用户名", "login.password": "密码", "login.button": "登录",
    "login.hint": "你的 keelAuth 账号。管理员（keelauth-admins 组）在这里管理 keelAuth；其他人可以改自己的密码。",
    "login.noadmin": "keelAuth 还没有管理员：在 keelOS 的“账号”标签里建一个，或在虚拟机控制台上运行 keelauthd admin 名字。",
    "srv.bad_login": "用户名或密码不对。", "srv.disabled": "这个账号已停用。", "srv.too_many": "登录失败次数太多，请等几分钟。",
    "srv.csrf": "页面过期了，请刷新。", "srv.not_admin": "只有 keelauth-admins 组的人能做这件事。", "srv.login": "请先登录。",
    "srv.bad_password": "当前密码不对。", "srv.must_change": "请先修改密码。", "srv.weak_password": "keelAuth 不接受这个密码",
    "nav.overview": "概览", "nav.users": "用户", "nav.groups": "组", "nav.access": "接入", "nav.backup": "备份", "nav.settings": "设置",
    "ov.version": "版本", "ov.addresses": "地址", "ov.uptime": "keelauthd 已运行", "ov.lastbackup": "最近备份", "ov.never": "还没有",
    "ov.alerts": "需要留意", "ov.services": "服务", "ov.running": "运行中", "ov.down": "没有运行", "ov.registered": "已连接", "ov.standalone": "不归 keel 管（没有种子盘）：单独运行",
    "ov.notyet": "还没连上", "ov.accounts": "账号", "ov.ways": "接入方式",
    "alert.engine": "Kanidm（账号引擎）没有就绪：{0}。", "alert.service_down": "{0} 没有运行。",
    "alert.radius_behind": "FreeRADIUS 还没有拿到最新的改动。",
    "alert.missing_nt": "{0} 还没有 Wi-Fi 和共享用的密码：在这里重设一次他们的密码。",
    "alert.no_admin": "keelAuth 没有管理员（keelauth-admins 组是空的）。", "alert.no_backup": "还没有备份。",
    "alert.old_backup": "最近一次备份已经超过两天。",
    "users.new": "新用户", "users.add": "添加", "users.name": "用户名", "users.display": "姓名", "users.mail": "邮箱",
    "users.groups": "组", "users.password": "密码", "users.setat": "密码设于",
    "users.namehint": "小写字母、数字、- 和 _，字母开头：登录时输入的名字（例如 anna）。",
    "users.autopw": "由 keelAuth 生成密码（只显示一次）", "users.mustchange": "下次登录时必须改成自己的密码",
    "users.edit": "修改 {0}", "users.reset": "重设密码", "users.resettitle": "给 {0} 设新密码",
    "users.resetnote": "旧密码在所有地方马上失效：LDAP、SSO、Wi-Fi、共享。",
    "users.disable": "停用", "users.enable": "启用", "users.disabled": "已停用", "users.admin": "管理员", "users.mustshort": "须改密码",
    "users.nont": "没有 Wi-Fi/共享密码", "users.nonttip": "这个人的密码不是在 keelAuth 里设的：在这里重设一次，Wi-Fi 和共享才能用。",
    "users.disableq": "停用 {0}？所有地方（LDAP、SSO、Wi-Fi、共享）都登录不了，直到重新启用。",
    "users.deleteq": "永久删除 {0}？账号、组成员关系、密码都没有了；共享里他的文件还在。",
    "users.none": "还没有用户。", "users.pwset": "密码已设好", "users.pwfor": "{0} 的密码",
    "users.pwonce": "把这个密码交给本人（只显示这一次）。本人在这个页面登录后改成自己的。",
    "users.note": "一个账号到处用：LDAP、SSO、Wi-Fi（RADIUS）和 keelNAS 的共享都是同一个用户名和密码。密码只在这里设。",
    "pw.title": "修改密码", "pw.own": "改我的密码", "pw.old": "当前密码", "pw.new": "新密码", "pw.again": "再输一次新密码",
    "pw.change": "修改密码", "pw.changed": "密码已修改", "pw.mismatch": "两次输入的新密码不一样。",
    "pw.must": "你的密码是管理员设的：现在换成你自己的。",
    "pw.useronly": "只有管理员能管理 keelAuth；你可以在这里改自己的密码。",
    "pw.rules": "至少 10 个字符，而且不能太好猜（不用常见的词、简单的规律）。这个密码 LDAP、SSO、Wi-Fi、共享都用。",
    "groups.group": "组", "groups.new": "新组", "groups.add": "添加", "groups.name": "组名", "groups.desc": "说明", "groups.members": "成员",
    "groups.edit": "修改 {0}", "groups.builtin": "内置", "groups.admindesc": "keelAuth 的管理员",
    "groups.adminnote": "keelauth-admins 的成员管理 keelAuth。最后一个不能去掉。",
    "groups.deleteq": "删除组 {0}？成员不受影响；这个组原来允许的（SSO 应用、共享）不再生效。",
    "groups.nousers": "还没有可以加的用户。", "groups.note": "组决定谁能登录某个 SSO 应用、谁能连 Wi-Fi，接了 keelNAS 以后还决定谁能打开哪个共享。",
    "acc.ldap": "LDAP", "acc.sso": "SSO（OIDC）", "acc.radius": "RADIUS", "acc.radiusclients": "RADIUS 客户端",
    "acc.fill": "对方那边怎么填", "acc.ca": "下载 CA 证书",
    "ldap.for": "给用 LDAP 查用户、验密码的设备和程序：打印机和复印机（通讯录、登录）、Linux 机器、邮件（Dovecot）、GitLab、Redmine 等自建应用。只读。",
    "ldap.server": "服务器", "ldap.port": "端口", "ldap.security": "加密", "ldap.ldaps": "LDAPS（一开始就是 SSL/TLS；不是 StartTLS）",
    "ldap.binddn": "绑定 DN（用户）", "ldap.bindpw": "绑定密码", "ldap.userfilter": "用户过滤", "ldap.loginattr": "登录属性（uid）",
    "ldap.attrs": "其他属性", "ldap.groupfilter": "组过滤",
    "ldap.reset": "换绑定密码", "ldap.resetq": "生成新的绑定密码？用旧密码的设备都要改。", "ldap.reset.done": "新的绑定密码已生成",
    "ldap.examples": "配置示例", "ldap.exfor": "{0} 的配置", "ldap.exfile": "文件：", "ldap.exholder": "{0} 处填设备账号的密码（建好或换新密码时显示一次）。", "ldap.devnew": "新设备账号", "ldap.devadd": "建", "ldap.devfor": "每台打印机、Linux 机器或应用一个账号：只能读用户、组和邮箱地址，可以单独吊销。密码是一串很长的令牌，只显示一次。", "ldap.devname": "名字", "ldap.devdesc": "是什么", "ldap.devdescex": "二楼复印机", "ldap.devmade": "设备账号 {0}", "ldap.devonce": "只显示这一次：填进设备。keelAuth 不会再显示（“新密码”可以再生成一个）。", "ldap.exwith": "带这个密码的示例", "ldap.devnewpwq": "给 {0} 生成新密码？旧的马上失效。", "ldap.devdelq": "删除设备账号 {0}？这台设备再也读不了 keelAuth 的用户。", "ldap.devices": "设备账号", "ldap.devnone": "还没有设备账号：每台打印机、Linux 机器、应用建一个。", "ldap.devpwat": "密码生成于", "ldap.devmissing": "keelAuth 记着这个账号，Kanidm 里却没有（恢复了较早的备份）：生成新密码就会重建。", "ldap.devmissingb": "缺失", "ldap.devnewpw": "新密码", "ldap.devpw": "设备账号的密码（建好时显示）", "ldap.mailattr": "邮箱属性", "ldap.nameattr": "姓名属性", "ldap.member": "成员：", "ldap.shared": "共用的只读账号（短密码，没有邮箱地址）", "ldap.sharedfor": "给密码栏放不下设备账号令牌的设备：能查用户、验密码，但 Kanidm 不给密码登录的会话邮箱地址。所有设备共用这一个。", "ldap.note": "匿名读取已关闭。要验证某人密码的应用先用设备账号找到这个人，再用这个人自己绑定（name=<用户名>,<Base DN>）。证书上的名字是 {0}：检查证书的设备要能在办公室 DNS（或自己的 hosts）里查到 {0}，并装 keelAuth 的 CA。", "rad.fillap": "AP（或 VPN 网关）上填", "rad.acct": "计费（Accounting）", "rad.acctv": "关（不用）", "rad.fillclient": "手机、电脑上填（只在它们问的时候）", "rad.inner": "第二阶段（内层）", "rad.ca": "CA 证书", "rad.domain": "域名（要核对的服务器名）", "rad.identity": "身份", "rad.anon": "匿名身份", "rad.anonv": "空着，或 anonymous", "rad.note": "大多数手机第一次会问要不要信任服务器：看到的名字应该是 {0}。Android 11 以后要选 CA 和填域名：先装 CA（.cer），选它，域名填 {0}。iPhone 和 Mac：装 Apple 描述文件，或者第一次登录时信任证书。Windows 第一次会问；统一管理的电脑设“连接到这些服务器：{0}”，并把 CA 设为受信任的根证书。", "rad.fp": "CA 指纹：SHA-256 {0} · SHA-1 {1}", "cert.warn": "已采用，注意：{0}", "cert.office": "用办公室自己的证书…", "cert.replace": "换办公室的证书…", "cert.use": "采用", "cert.officefor": "办公室自己的 CA（或公共 CA）给 {0} 签的证书，连同私钥。LDAPS、单点登录、这个页面和 Wi-Fi（PEAP）都换成它；keelAuth 自己的证书留着，“回到 keelAuth 自己的”可以换回去。", "cert.certfile": "证书（PEM）", "cert.certhint": "域名的证书，接着是中间证书和根证书（一个文件，或依次粘贴）。", "cert.keyfile": "私钥（PEM）", "cert.keyhint": "不加密的（PKCS#8、RSA 或 EC）。私钥已在证书文件里时空着。", "cert.officenote": "keelAuth 会检查：私钥和证书配对、证书上有这个域名、现在有效、是给 TLS 服务器用的、RSA 密钥至少 2048 位、证书链通到根证书。Kanidm 和 FreeRADIUS 会重启（几秒）；它们不接受时 keelAuth 保持原来的证书。", "cert.days": "还剩 {0} 天", "cert.back": "回到 keelAuth 自己的", "cert.backq": "回到 keelAuth 自己的证书？只信任办公室 CA 的设备之后要改为信任 keelAuth 的 CA。", "cert.backdone": "已换回 keelAuth 自己的证书", "cert.usedone": "已采用办公室的证书", "cert.inuse": "正在用", "cert.inuseoffice": "办公室的证书（{0} 上传）", "cert.inuseown": "keelAuth 自己的（它的 CA 签的）", "cert.anchor": "设备要信任的 CA", "cert.pem": "PEM（.crt）", "cert.der": "DER（.cer：Windows、Android）", "cert.apple": "Apple 描述文件", "cert.public": "设备也可以不登录直接取：https://{0}/ca/keelauth-ca.crt（还有 .cer、.mobileconfig）。", "cert.server": "LDAPS、单点登录、本页", "cert.radius": "Wi-Fi（PEAP）", "cert.ownca": "keelAuth 自己的 CA", "cert.notused": "留着，没在用", "cert.forOffice": "keelAuth 正在用办公室自己的证书。keelAuth 自己的 CA 和证书还留着（照常续期），可以换回去。",
    "sso.for": "网页应用的单点登录（OpenID Connect）：在 keelAuth 的页面登录一次，各个应用都进得去。每个应用先在这里登记，再把得到的信息填进应用的 OIDC 设置。",
    "sso.new": "登记应用", "sso.add": "登记", "sso.name": "名字", "sso.namehint": "简短、小写：它就是 client ID（例如 gitlab）。",
    "sso.display": "显示为", "sso.redirects": "回调地址", "sso.redirectshint": "应用的回调地址，一行一个（在应用的 OIDC 设置里，例如 https://gitlab.office.lan/users/auth/openid_connect/callback）。",
    "sso.landing": "应用地址（可选）", "sso.who": "谁能登录", "sso.everyone": "所有人",
    "sso.pkce": "要求 PKCE（S256）：只有不支持的旧应用才关掉", "sso.nopkce": "无 PKCE",
    "sso.edit": "修改 {0}", "sso.secret": "密钥", "sso.newsecret": "换密钥", "sso.resetq": "给 {0} 生成新的 client secret？应用换上新的之前登录不了。",
    "sso.deleteq": "移除 {0}？经 keelAuth 的登录会停掉。", "sso.none": "还没有登记应用。",
    "sso.issuer": "Issuer", "sso.discovery": "发现地址（Discovery URL）", "sso.clientid": "上面列表里应用的名字", "sso.clientsecret": "登记时显示（“密钥”按钮）",
    "sso.scopes": "Scopes", "sso.auth": "客户端认证", "sso.userclaim": "用户名的 claim",
    "sso.note": "登录页是 keelAuth 自己的（Kanidm，https://<域名>:8443）：浏览器要能用域名访问 keelAuth（办公室 DNS 里加一条，或 hosts 文件），并信任 keelAuth 的证书（在 LDAP 标签下载 CA）；Kanidm 的登录只在这个名字下能用。keelOS 自己的登录两样都不需要：keel 在自己的地址上显示这个页面。",
    "sso.noteip": "这台 keelAuth 用固定的局域网地址当 origin（IP 模式）：不需要 DNS，应用和浏览器只要信任 keelAuth 的 CA。这个模式下没有通行密钥（passkey）。",
    "sso.short": "用户名不带 @域名（alice，不是 alice@域名）：大多数应用直接拿它当登录名", "sso.connect": "对接", "sso.connect1": "{0}：把这些填进应用", "sso.redirectsset": "在这里登记（修改）；要和应用里的完全一样", "sso.groupclaim": "组的 claim", "sso.claimex": "例如 {0}", "sso.rolesfor": "{0}（{1}）给这些 keelAuth 组权限：", "sso.rolegroup": "keelAuth 组", "sso.rolemeans": "在 {0} 里", "sso.makegroup": "建这个组", "sso.groupok": "已有", "sso.groupmade": "已建组 {0}：在“组”页面加成员", "sso.roleshint": "把人放进这些组（“组”页面）。一个组都不在的人那边会拒绝；改动 15 分钟内生效。",
    "sso.for1": "{0}：把这些填进应用", "sso.secretnote": "密钥只放在应用的设置里。",
    "rad.for": "给办公室的企业 Wi-Fi（WPA2/WPA3-Enterprise）和 VPN：每个人用自己的 keelAuth 用户名和密码，不用共享一个 Wi-Fi 密码；停用的人马上连不上。",
    "rad.new": "新客户端", "rad.add": "添加", "rad.name": "名字", "rad.address": "地址", "rad.secret": "共享密钥",
    "rad.addresshint": "AP（或 VPN 网关）的 IP 地址；好几台时可以填网段（192.168.1.0/24）。",
    "rad.secrethint": "空着：keelAuth 生成一个。", "rad.secretkeep": "空着：保留现在的。",
    "rad.edit": "修改 {0}", "rad.deleteq": "移除客户端 {0}？它再也问不了 keelAuth。", "rad.none": "还没有客户端：每台 AP 加一个。",
    "rad.who": "谁能用：", "rad.everyone": "所有用户", "rad.users": "{0} 个用户能登录",
    "rad.missing": "以下的人在这里重设一次密码之前没有 Wi-Fi 密码：{0}",
    "rad.server": "RADIUS 服务器", "rad.port": "端口", "rad.secretper": "每个客户端各一个，见上面的列表", "rad.security": "安全类型", "rad.eap": "EAP 方式",
    "rad.login": "手机、电脑上登录", "rad.loginv": "本人的 keelAuth 用户名和密码",
    "rad.for1": "{0}：把这些填进 AP", "rad.shownote": "共享密钥以后在列表里还能看到（“显示”）。",
    "bk.now": "马上备份", "bk.keep": "保留", "bk.keepn": "保留几份", "bk.done": "备份好了", "bk.none": "还没有备份。",
    "bk.time": "时间", "bk.size": "大小", "bk.file": "文件", "bk.restore": "恢复",
    "bk.restoreq": "恢复 {0} 的备份？用户、组、密码、应用都回到那个时候，之后的改动都会丢掉。keelAuth 的登录（Kanidm）会停一下。",
    "bk.restored": "已恢复", "bk.note": "keelAuth 每天自动备份一次，保留最新的 {0} 份（{1}）。可以下载一份放到别处；里面 Wi-Fi 和共享用的密码哈希是加密的：在另一台 keelAuth 上恢复要这台的恢复密钥。", "bk.download": "下载",
    "set.ai": "AI 管理", "set.sync": "keelNAS", "set.cert": "证书", "set.general": "常规",
    "lock.title": "keelAuth 已锁定", "lock.why": "保护 Wi-Fi 和共享密码哈希的密钥在这里打不开（数据盘来自另一台 keelAuth，或者这台换了系统盘）。给出之前什么都用不了。",
    "lock.input": "恢复密钥（KAR1-…）或恢复口令", "lock.button": "解锁", "lock.hint": "keelOS 管的 keelAuth：keelOS 的“账号”标签 → 恢复密钥；单独运行的 keelAuth：设置 → 常规里设的恢复口令。",
    "srv.locked": "keelAuth 已锁定：先给出恢复密钥或恢复口令。", "srv.need_recovery_key": "这份备份是另一台 keelAuth 做的：要它的恢复密钥（keelOS：账号 → 恢复密钥）或恢复口令。",
    "srv.bad_key": "这个恢复密钥或口令不对。",
    "gen.tz": "时区", "gen.tzkeel": "{0}（keelOS 的设置）", "gen.tzfor": "本页的时间按这个时区显示（办公室所在地），不按浏览器的。",
    "gen.tztitle": "时区", "gen.mk": "密码哈希的保护", "gen.mkkeel": "用 keelOS 的密钥包着", "gen.mkpass": "用恢复口令包着（{0} 设的）",
    "gen.mknone": "没有保护：请设恢复口令", "gen.setpass": "设恢复口令", "gen.changepass": "换恢复口令",
    "gen.passfor": "Wi-Fi 和共享的密码哈希用一把密钥加密，这把密钥用这个口令包着：单拿到备份或数据盘都看不出哈希。在别处恢复备份、换了系统盘以后都要它。请妥善保管：没有人能找回。",
    "gen.pass": "口令（至少 12 个字符）", "gen.pass2": "再输一次", "gen.passdiff": "两次输入的不一样。", "gen.passset": "恢复口令已设好",
    "gen.mkkeelnote": "密钥由 keelOS 保管：在别的主机上恢复备份时，keelOS 的“账号”标签里有恢复密钥。",
    "bk.upload": "上传备份…", "bk.uploaded": "已上传：{0}", "bk.keytitle": "恢复 {0}", "bk.keyfor": "这份备份是另一台 keelAuth 做的。用它的恢复密钥（原来那台主机上 keelOS 的“账号” → 恢复密钥）或恢复口令打开。",
    "ov.mk": "密码哈希",
    "alert.master_key_unprotected": "请设恢复口令（设置 → 常规）：在那之前，保护 Wi-Fi 和共享密码哈希的密钥明文放在数据盘上和每一份备份里。",
    "alert.locked": "keelAuth 已锁定：请给出恢复密钥或恢复口令。",
    "ai.title": "AI 管理（MCP）", "ai.new": "新令牌", "ai.for": "助手（Claude 等支持 MCP 的）可以管理 keelAuth：查看和添加用户、重设密码、组、SSO 应用、RADIUS 客户端、备份。给它一个单独的令牌；不用了在这里吊销。",
    "ai.connect": "连接", "ai.note": "keel-mcp 随 keelOS 提供；指纹用来核对 keelAuth 的证书：{0}", "ai.made": "{0}", "ai.token": "令牌", "ai.command": "命令",
    "tok.make": "生成", "tok.name": "名字", "tok.namehint": "给什么、给谁用（例如“Anna 笔记本上的 Claude”）。", "tok.none": "还没有。",
    "tok.created": "生成于", "tok.used": "最近使用", "tok.revoke": "吊销", "tok.revokeq": "吊销 {0}？用它的程序马上就用不了。",
    "sync.title": "keelNAS 同步密钥", "sync.new": "新密钥", "sync.for": "从 keelAuth 取用户的 keelNAS 用自己的一把密钥读用户（带 Windows 共享用的密码哈希）。", "sync.key": "密钥",
    "cert.title": "证书", "cert.for": "keelAuth 有自己的证书颁发机构（CA）：LDAPS、SSO 登录页和这个页面都用它签的证书。设备和浏览器装一次 CA 证书，三样都信任。",
    "cert.domain": "域名", "cert.origin": "SSO 地址", "cert.fp": "本页证书（SHA-256）",
    "cert.note": "域名在建 keelAuth 时定下，以后不能改（每个 SSO 应用的 issuer 里都有它）。设备要能在 DNS 里查到它，或者用地址。",
  },
};

export const languages = ["zh", "en"];

// framed: the page is in keel's 账号 tab (same origin): it follows keel's language and theme
export const framed = (() => { try { return window.top !== window && !!window.top.location.href; } catch (_) { return false; } })();

function pick() {
  try {
    const s = (framed && localStorage.getItem("keel.lang")) || localStorage.getItem("keelauth.lang");
    if (s && dict[s]) return s;
  } catch (_) { /* no storage */ }
  for (const l of navigator.languages || [navigator.language || "en"]) {
    const k = String(l).toLowerCase().slice(0, 2);
    if (dict[k]) return k;
  }
  return "en";
}

let lang = pick();
document.documentElement.lang = lang === "zh" ? "zh-CN" : lang;

export function getLang() { return lang; }

export function setLang(l) {
  if (!dict[l]) return;
  lang = l;
  document.documentElement.lang = l === "zh" ? "zh-CN" : l;
  try { localStorage.setItem("keelauth.lang", l); } catch (_) { /* no storage */ }
}

export function t(key, ...args) {
  const s = dict[lang][key] ?? dict.en[key] ?? key;
  return args.length ? s.replace(/\{(\d)\}/g, (_, i) => (args[i] ?? "")) : s;
}

export function tr(key, fallback, ...args) {
  const v = t(key, ...args);
  return v === key ? fallback : v;
}

export function langName(l) { return dict[l]["lang.name"]; }

// fmtTime is time.js's (the zone of the place, never the browser's: keelOS docs/47).
export { fmtTime } from "./time.js";
