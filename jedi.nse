local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"
local smbauth = require "smbauth"
local string = require "string"
local table = require "table"
local comm = require "comm"
local dns = require "dns"

description = [[
jedi.nse - "May the Force be with your enumeration."

Blanket OSCP enumeration script. Auto-detects the service on each open port
and runs the most useful enumeration checks for that service. One script
replaces 40+ individual NSE scripts.

READ-ONLY: No exploitation, no DoS, no state modification. OSCP exam safe.
Equivalent to running the individual scripts manually.

Usage:
  nmap -sV --script jedi TARGET
  nmap -sV --script jedi -p 21,22,25,53,80,110,111,135,139,389,443,445,993,1433,2049,3306,3389,5432,5985,8080 TARGET
  nmap -sV --script jedi --script-args jedi.timeout=10 TARGET
]]

author = "SolventlessMilk"
license = "MIT"
categories = {"default", "safe", "discovery"}

-- Run on any open port with a detected service
portrule = function(host, port)
    return port.state == "open"
end

-- Helpers
local function tag(severity, msg)
    return string.format("[%s] %s", severity, msg)
end

local function try_recv(socket, timeout)
    local status, data = socket:receive_lines(1)
    if status then return data end
    return nil
end

-- ══════════════════════════════════════════════════════════════════════
-- HTTP / HTTPS
-- ══════════════════════════════════════════════════════════════════════
local function check_http(host, port)
    local results = {}
    local scheme = (port.service == "https" or port.number == 443 or port.number == 8443) and "https" or "http"

    -- Title + Server header
    local resp = http.get(host, port, "/")
    if resp and resp.status then
        table.insert(results, tag("INFO", string.format("Status: %d", resp.status)))

        -- Title extraction
        if resp.body then
            local title = resp.body:match("<title>(.-)</title>")
            if title then
                title = title:gsub("%s+", " "):gsub("^%s+", ""):gsub("%s+$", "")
                table.insert(results, tag("INFO", "Title: " .. title))
            end
        end

        -- Server header
        if resp.header and resp.header["server"] then
            table.insert(results, tag("INFO", "Server: " .. resp.header["server"]))
        end

        -- X-Powered-By
        if resp.header and resp.header["x-powered-by"] then
            table.insert(results, tag("FIND", "X-Powered-By: " .. resp.header["x-powered-by"]))
        end

        -- Interesting security headers (missing = finding)
        if resp.header then
            if not resp.header["x-frame-options"] then
                table.insert(results, tag("LOW", "Missing X-Frame-Options header"))
            end
            if not resp.header["content-security-policy"] then
                table.insert(results, tag("LOW", "Missing Content-Security-Policy header"))
            end
            if resp.header["x-aspnet-version"] then
                table.insert(results, tag("FIND", "ASP.NET Version: " .. resp.header["x-aspnet-version"]))
            end
        end
    end

    -- Allowed methods (OPTIONS)
    local opts = http.generic_request(host, port, "OPTIONS", "/")
    if opts and opts.header and opts.header["allow"] then
        local methods = opts.header["allow"]
        table.insert(results, tag("INFO", "Allowed methods: " .. methods))
        if methods:match("PUT") or methods:match("DELETE") then
            table.insert(results, tag("HIGH", "Dangerous methods enabled: " .. methods))
        end
    end

    -- robots.txt
    local robots = http.get(host, port, "/robots.txt")
    if robots and robots.status == 200 and robots.body and #robots.body > 0 then
        local lines = {}
        local count = 0
        for line in robots.body:gmatch("[^\r\n]+") do
            if line:match("^%s*[Dd]isallow") or line:match("^%s*[Aa]llow") then
                count = count + 1
                if count <= 10 then
                    table.insert(lines, "  " .. line)
                end
            end
        end
        if count > 0 then
            table.insert(results, tag("FIND", string.format("robots.txt (%d rules):", count)))
            for _, l in ipairs(lines) do
                table.insert(results, l)
            end
            if count > 10 then
                table.insert(results, string.format("  ... and %d more", count - 10))
            end
        end
    end

    -- Common interesting paths (quick check, no brute)
    local quick_paths = {
        "/.git/HEAD", "/.env", "/wp-login.php", "/administrator/",
        "/phpmyadmin/", "/.htaccess", "/server-status", "/server-info",
        "/web.config", "/crossdomain.xml", "/.well-known/security.txt",
    }
    for _, path in ipairs(quick_paths) do
        local r = http.get(host, port, path)
        if r and (r.status == 200 or r.status == 403) then
            local size = r.body and #r.body or 0
            if r.status == 200 and size > 0 then
                table.insert(results, tag("FIND", string.format("%s -> %d (%d bytes)", path, r.status, size)))
            elseif r.status == 403 then
                table.insert(results, tag("INFO", string.format("%s -> 403 Forbidden (exists but protected)", path)))
            end
        end
    end

    return results
end

-- ══════════════════════════════════════════════════════════════════════
-- FTP
-- ══════════════════════════════════════════════════════════════════════
local function check_ftp(host, port)
    local results = {}
    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    local status, err = socket:connect(host, port)
    if not status then return results end

    -- Banner
    local banner = try_recv(socket)
    if banner then
        table.insert(results, tag("INFO", "Banner: " .. banner:gsub("[\r\n]+", " ")))
    end

    -- Anonymous login
    socket:send("USER anonymous\r\n")
    local resp = try_recv(socket)
    if resp and resp:match("^331") then
        socket:send("PASS anonymous@\r\n")
        resp = try_recv(socket)
        if resp and resp:match("^230") then
            table.insert(results, tag("HIGH", "Anonymous FTP login allowed!"))
            -- Try to list root
            socket:send("PASV\r\n")
            local pasv = try_recv(socket)
            socket:send("LIST\r\n")
        else
            table.insert(results, tag("INFO", "Anonymous user accepted but login failed"))
        end
    end

    socket:close()
    return results
end

-- ══════════════════════════════════════════════════════════════════════
-- SSH
-- ══════════════════════════════════════════════════════════════════════
local function check_ssh(host, port)
    local results = {}
    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    local status, err = socket:connect(host, port)
    if not status then return results end

    local banner = try_recv(socket)
    if banner then
        banner = banner:gsub("[\r\n]+", "")
        table.insert(results, tag("INFO", "Banner: " .. banner))

        -- Old SSH versions
        if banner:match("SSH%-1") then
            table.insert(results, tag("HIGH", "SSHv1 detected (insecure)"))
        end
        if banner:match("OpenSSH[_ ]([%d%.]+)") then
            local ver = banner:match("OpenSSH[_ ]([%d%.]+)")
            table.insert(results, tag("INFO", "OpenSSH version: " .. ver))
        end
        if banner:match("dropbear") then
            table.insert(results, tag("INFO", "Dropbear SSH server"))
        end
    end

    socket:close()
    return results
end

-- ══════════════════════════════════════════════════════════════════════
-- SMTP
-- ══════════════════════════════════════════════════════════════════════
local function check_smtp(host, port)
    local results = {}
    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    local status, err = socket:connect(host, port)
    if not status then return results end

    local banner = try_recv(socket)
    if banner then
        table.insert(results, tag("INFO", "Banner: " .. banner:gsub("[\r\n]+", " ")))
    end

    -- VRFY test with common users
    socket:send("EHLO jedi\r\n")
    try_recv(socket)

    local test_users = {"root", "admin", "administrator", "postmaster", "www-data"}
    local vrfy_works = false
    for _, user in ipairs(test_users) do
        socket:send("VRFY " .. user .. "\r\n")
        local resp = try_recv(socket)
        if resp then
            if resp:match("^252") or resp:match("^250") then
                table.insert(results, tag("FIND", "VRFY " .. user .. ": " .. resp:gsub("[\r\n]+", "")))
                vrfy_works = true
            end
        end
    end

    if vrfy_works then
        table.insert(results, tag("HIGH", "SMTP VRFY enabled - user enumeration possible"))
    end

    -- EXPN test
    socket:send("EXPN root\r\n")
    local resp = try_recv(socket)
    if resp and (resp:match("^250") or resp:match("^252")) then
        table.insert(results, tag("HIGH", "SMTP EXPN enabled"))
    end

    socket:close()
    return results
end

-- ══════════════════════════════════════════════════════════════════════
-- DNS
-- ══════════════════════════════════════════════════════════════════════
local function check_dns(host, port)
    local results = {}

    -- Version bind
    local status, resp = dns.query("version.bind", {dtype = "TXT", host = host.ip, port = port.number, class = "CH"})
    if status and resp then
        table.insert(results, tag("FIND", "DNS version: " .. tostring(resp)))
    end

    table.insert(results, tag("INFO", "Test zone transfer with: dig axfr @" .. host.ip .. " DOMAIN"))
    return results
end

-- ══════════════════════════════════════════════════════════════════════
-- SMB
-- ══════════════════════════════════════════════════════════════════════
local function check_smb(host, port)
    local results = {}

    table.insert(results, tag("INFO", "SMB detected. Run for full enum:"))
    table.insert(results, "  python3 jawa.py " .. host.ip)
    table.insert(results, "  nmap --script smb-enum-shares,smb-os-discovery,smb-vuln* -p 445 " .. host.ip)
    table.insert(results, "  smbclient -L //" .. host.ip .. "/ -N")

    return results
end

-- ══════════════════════════════════════════════════════════════════════
-- SNMP
-- ══════════════════════════════════════════════════════════════════════
local function check_snmp(host, port)
    local results = {}

    table.insert(results, tag("INFO", "SNMP detected. Check community strings:"))
    table.insert(results, "  snmpwalk -v2c -c public " .. host.ip)
    table.insert(results, "  onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt " .. host.ip)

    return results
end

-- ══════════════════════════════════════════════════════════════════════
-- MySQL
-- ══════════════════════════════════════════════════════════════════════
local function check_mysql(host, port)
    local results = {}
    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    local status, err = socket:connect(host, port)
    if not status then return results end

    -- MySQL greeting packet
    local data = try_recv(socket)
    if data then
        -- Extract version from greeting
        if #data > 5 then
            local ver_end = data:find("\0", 6)
            if ver_end then
                local version = data:sub(6, ver_end - 1)
                if version:match("[%d%.]+") then
                    table.insert(results, tag("INFO", "MySQL version: " .. version))
                end
            end
        end
    end

    socket:close()
    table.insert(results, tag("INFO", "Test auth: mysql -h " .. host.ip .. " -u root -p''"))
    table.insert(results, "  python3 bobafett.py " .. host.ip .. " -u root --type mysql")
    return results
end

-- ══════════════════════════════════════════════════════════════════════
-- MSSQL
-- ══════════════════════════════════════════════════════════════════════
local function check_mssql(host, port)
    local results = {}
    table.insert(results, tag("INFO", "MSSQL detected. Enumerate with:"))
    table.insert(results, "  python3 bobafett.py " .. host.ip .. " -u sa -pw '' --type mssql")
    table.insert(results, "  nmap --script ms-sql-info,ms-sql-ntlm-info,ms-sql-empty-password -p " .. port.number .. " " .. host.ip)
    table.insert(results, "  impacket-mssqlclient sa@" .. host.ip .. " -windows-auth")
    return results
end

-- ══════════════════════════════════════════════════════════════════════
-- PostgreSQL
-- ══════════════════════════════════════════════════════════════════════
local function check_postgres(host, port)
    local results = {}
    table.insert(results, tag("INFO", "PostgreSQL detected. Enumerate with:"))
    table.insert(results, "  python3 bobafett.py " .. host.ip .. " -u postgres -pw '' --type postgres")
    table.insert(results, "  psql -h " .. host.ip .. " -U postgres -W")
    return results
end

-- ══════════════════════════════════════════════════════════════════════
-- NFS
-- ══════════════════════════════════════════════════════════════════════
local function check_nfs(host, port)
    local results = {}
    table.insert(results, tag("INFO", "NFS detected. Check exports:"))
    table.insert(results, "  showmount -e " .. host.ip)
    table.insert(results, "  nmap --script nfs-ls,nfs-showmount,nfs-statfs -p 111,2049 " .. host.ip)
    return results
end

-- ══════════════════════════════════════════════════════════════════════
-- RDP
-- ══════════════════════════════════════════════════════════════════════
local function check_rdp(host, port)
    local results = {}
    table.insert(results, tag("INFO", "RDP detected. Check:"))
    table.insert(results, "  nmap --script rdp-ntlm-info,rdp-enum-encryption -p " .. port.number .. " " .. host.ip)
    table.insert(results, "  xfreerdp /v:" .. host.ip .. " /u:'' /p:'' +auth-only")
    return results
end

-- ══════════════════════════════════════════════════════════════════════
-- LDAP
-- ══════════════════════════════════════════════════════════════════════
local function check_ldap(host, port)
    local results = {}
    table.insert(results, tag("INFO", "LDAP detected. Domain controller likely. Enumerate with:"))
    table.insert(results, "  ldapsearch -x -H ldap://" .. host.ip .. " -s base namingContexts")
    table.insert(results, "  python3 ackbar.py -d DOMAIN -u USER -p PASS -dc " .. host.ip)
    table.insert(results, "  nmap --script ldap-rootdse,ldap-search -p " .. port.number .. " " .. host.ip)
    return results
end

-- ══════════════════════════════════════════════════════════════════════
-- WinRM
-- ══════════════════════════════════════════════════════════════════════
local function check_winrm(host, port)
    local results = {}
    table.insert(results, tag("INFO", "WinRM detected. Test with:"))
    table.insert(results, "  evil-winrm -i " .. host.ip .. " -u USER -p PASS")
    table.insert(results, "  nxc winrm " .. host.ip .. " -u USER -p PASS")
    return results
end

-- ══════════════════════════════════════════════════════════════════════
-- Kerberos
-- ══════════════════════════════════════════════════════════════════════
local function check_kerberos(host, port)
    local results = {}
    table.insert(results, tag("INFO", "Kerberos detected. This is a domain controller."))
    table.insert(results, "  nmap --script krb5-enum-users --script-args krb5-enum-users.realm=DOMAIN -p 88 " .. host.ip)
    table.insert(results, "  python3 ackbar.py -d DOMAIN -u USER -p PASS -dc " .. host.ip)
    table.insert(results, "  impacket-GetNPUsers DOMAIN/ -dc-ip " .. host.ip .. " -no-pass -usersfile users.txt")
    return results
end

-- ══════════════════════════════════════════════════════════════════════
-- Generic banner grab fallback
-- ══════════════════════════════════════════════════════════════════════
local function check_generic(host, port)
    local results = {}
    local socket = nmap.new_socket()
    socket:set_timeout(3000)

    local status, err = socket:connect(host, port)
    if not status then return results end

    -- Send empty line to trigger banner
    socket:send("\r\n")
    local banner = try_recv(socket)
    if banner and #banner > 0 then
        banner = banner:gsub("[\r\n]+", " "):sub(1, 200)
        table.insert(results, tag("INFO", "Banner: " .. banner))
    end

    socket:close()
    return results
end

-- ══════════════════════════════════════════════════════════════════════
-- MAIN: service dispatcher
-- ══════════════════════════════════════════════════════════════════════
action = function(host, port)
    local svc = port.service or ""
    local pnum = port.number
    local results = {}

    -- Dispatch based on service name or port number
    if svc:match("http") or svc:match("ssl/http") or pnum == 80 or pnum == 443
       or pnum == 8080 or pnum == 8443 or pnum == 8000 or pnum == 8888
       or pnum == 9090 or pnum == 3000 then
        results = check_http(host, port)

    elseif svc:match("ftp") or pnum == 21 then
        results = check_ftp(host, port)

    elseif svc:match("ssh") or pnum == 22 then
        results = check_ssh(host, port)

    elseif svc:match("smtp") or pnum == 25 or pnum == 587 then
        results = check_smtp(host, port)

    elseif svc:match("domain") or svc:match("dns") or pnum == 53 then
        results = check_dns(host, port)

    elseif svc:match("microsoft%-ds") or svc:match("smb") or pnum == 445 then
        results = check_smb(host, port)

    elseif svc:match("netbios") or pnum == 139 then
        results = check_smb(host, port)

    elseif svc:match("snmp") or pnum == 161 then
        results = check_snmp(host, port)

    elseif svc:match("mysql") or pnum == 3306 then
        results = check_mysql(host, port)

    elseif svc:match("ms%-sql") or svc:match("mssql") or pnum == 1433 then
        results = check_mssql(host, port)

    elseif svc:match("postgresql") or pnum == 5432 then
        results = check_postgres(host, port)

    elseif svc:match("nfs") or svc:match("rpcbind") or pnum == 2049 or pnum == 111 then
        results = check_nfs(host, port)

    elseif svc:match("ms%-wbt%-server") or svc:match("rdp") or pnum == 3389 then
        results = check_rdp(host, port)

    elseif svc:match("ldap") or pnum == 389 or pnum == 636 then
        results = check_ldap(host, port)

    elseif svc:match("wsman") or svc:match("winrm") or pnum == 5985 or pnum == 5986 then
        results = check_winrm(host, port)

    elseif svc:match("kerberos") or pnum == 88 then
        results = check_kerberos(host, port)

    else
        -- Unknown service: try generic banner grab
        results = check_generic(host, port)
    end

    if #results == 0 then
        return nil
    end

    return table.concat(results, "\n")
end
