# MyLog4Shell
# log4j RCE Exploitation Detection

You can use these commands and rules to search for exploitation attempts against log4j RCE vulnerability CVE-2021-44228

## Grep / Zgrep

This command searches for exploitation attempts in uncompressed files in folder `/var/log` - '/use/car/log' and all sub folders

```bash
sudo egrep -I -i -r '\$(\{|%7B)jndi:(ldap[s]?|rmi|dns|nis|iiop|corba|nds|http):/[^\n]+' /var/log
```

This command searches for exploitation attempts in compressed files in folder `/var/log` and all sub folders

```bash
sudo find /var/log -name \*.gz -print0 | xargs -0 zgrep -E -i '\$(\{|%7B)jndi:(ldap[s]?|rmi|dns|nis|iiop|corba|nds|http):/[^\n]+'
```

## Grep / Zgrep - Obfuscated Variants

These commands cover even the obfuscated variants but lack the file name in a match. 

This command searches for exploitation attempts in uncompressed files in folder `/var/log` and all sub folders

```bash
sudo find /var/log/ -type f -exec sh -c "cat {} | sed -e 's/\${lower://'g | tr -d '}' | egrep -I -i 'jndi:(ldap[s]?|rmi|dns|nis|iiop|corba|nds|http):'" \;
```

This command searches for exploitation attempts in compressed files in folder `/var/log` and all sub folders

```bash
sudo find /var/log/ -name '*.gz' -type f -exec sh -c "zcat {} | sed -e 's/\${lower://'g | tr -d '}' | egrep -i 'jndi:(ldap[s]?|rmi|dns|nis|iiop|corba|nds|http):'" \;
```

## Log4Shell-Rex

A massive regex to cover even the most obfuscated variants: https://github.com/back2root/log4shell-rex

```regex
(?:\$|%(?:25)*24|\\(?:0024|0{0,2}44))(?:{|%(?:25)*7[Bb]|\\(?:007[Bb]|0{0,2}173)).{0,30}?((?:[Jj]|%(?:25)*[46][Aa]|\\(?:00[46][Aa]|0{0,2}1[15]2)).{0,30}?(?:[Nn]|%(?:25)*[46][Ee]|\\(?:00[46][Ee]|0{0,2}1[15]6)).{0,30}?(?:[Dd]|%(?:25)*[46]4|\\(?:00[46]4|0{0,2}1[04]4)).{0,30}?(?:[Ii]|%(?:25)*[46]9|\\(?:00[46]9|0{0,2}1[15]1)|ı).{0,30}?(?::|%(?:25)*3[Aa]|\\(?:003[Aa]|0{0,2}72)).{0,30}?((?:[Ll]|%(?:25)*[46][Cc]|\\(?:00[46][Cc]|0{0,2}1[15]4)).{0,30}?(?:[Dd]|%(?:25)*[46]4|\\(?:00[46]4|0{0,2}1[04]4)).{0,30}?(?:[Aa]|%(?:25)*[46]1|\\(?:00[46]1|0{0,2}1[04]1)).{0,30}?(?:[Pp]|%(?:25)*[57]0|\\(?:00[57]0|0{0,2}1[26]0))(?:.{0,30}?(?:[Ss]|%(?:25)*[57]3|\\(?:00[57]3|0{0,2}1[26]3)))?|(?:[Rr]|%(?:25)*[57]2|\\(?:00[57]2|0{0,2}1[26]2)).{0,30}?(?:[Mm]|%(?:25)*[46][Dd]|\\(?:00[46][Dd]|0{0,2}1[15]5)).{0,30}?(?:[Ii]|%(?:25)*[46]9|\\(?:00[46]9|0{0,2}1[15]1)|ı)|(?:[Dd]|%(?:25)*[46]4|\\(?:00[46]4|0{0,2}1[04]4)).{0,30}?(?:[Nn]|%(?:25)*[46][Ee]|\\(?:00[46][Ee]|0{0,2}1[15]6)).{0,30}?(?:[Ss]|%(?:25)*[57]3|\\(?:00[57]3|0{0,2}1[26]3))|(?:[Nn]|%(?:25)*[46][Ee]|\\(?:00[46][Ee]|0{0,2}1[15]6)).{0,30}?(?:[Ii]|%(?:25)*[46]9|\\(?:00[46]9|0{0,2}1[15]1)|ı).{0,30}?(?:[Ss]|%(?:25)*[57]3|\\(?:00[57]3|0{0,2}1[26]3))|(?:.{0,30}?(?:[Ii]|%(?:25)*[46]9|\\(?:00[46]9|0{0,2}1[15]1)|ı)){2}.{0,30}?(?:[Oo]|%(?:25)*[46][Ff]|\\(?:00[46][Ff]|0{0,2}1[15]7)).{0,30}?(?:[Pp]|%(?:25)*[57]0|\\(?:00[57]0|0{0,2}1[26]0))|(?:[Cc]|%(?:25)*[46]3|\\(?:00[46]3|0{0,2}1[04]3)).{0,30}?(?:[Oo]|%(?:25)*[46][Ff]|\\(?:00[46][Ff]|0{0,2}1[15]7)).{0,30}?(?:[Rr]|%(?:25)*[57]2|\\(?:00[57]2|0{0,2}1[26]2)).{0,30}?(?:[Bb]|%(?:25)*[46]2|\\(?:00[46]2|0{0,2}1[04]2)).{0,30}?(?:[Aa]|%(?:25)*[46]1|\\(?:00[46]1|0{0,2}1[04]1))|(?:[Nn]|%(?:25)*[46][Ee]|\\(?:00[46][Ee]|0{0,2}1[15]6)).{0,30}?(?:[Dd]|%(?:25)*[46]4|\\(?:00[46]4|0{0,2}1[04]4)).{0,30}?(?:[Ss]|%(?:25)*[57]3|\\(?:00[57]3|0{0,2}1[26]3))|(?:[Hh]|%(?:25)*[46]8|\\(?:00[46]8|0{0,2}1[15]0))(?:.{0,30}?(?:[Tt]|%(?:25)*[57]4|\\(?:00[57]4|0{0,2}1[26]4))){2}.{0,30}?(?:[Pp]|%(?:25)*[57]0|\\(?:00[57]0|0{0,2}1[26]0))(?:.{0,30}?(?:[Ss]|%(?:25)*[57]3|\\(?:00[57]3|0{0,2}1[26]3)))?).{0,30}?(?::|%(?:25)*3[Aa]|\\(?:003[Aa]|0{0,2}72)).{0,30}?(?:\/|%(?:25)*2[Ff]|\\(?:002[Ff]|0{0,2}57)|\${)|(?:[Bb]|%(?:25)*[46]2|\\(?:00[46]2|0{0,2}1[04]2)).{0,30}?(?:[Aa]|%(?:25)*[46]1|\\(?:00[46]1|0{0,2}1[04]1)).{0,30}?(?:[Ss]|%(?:25)*[57]3|\\(?:00[57]3|0{0,2}1[26]3)).{0,30}?(?:[Ee]|%(?:25)*[46]5|\\(?:00[46]5|0{0,2}1[04]5)).{2,60}?(?::|%(?:25)*3[Aa]|\\(?:003[Aa]|0{0,2}72))(JH[s-v]|[\x2b\x2f-9A-Za-z][CSiy]R7|[\x2b\x2f-9A-Za-z]{2}[048AEIMQUYcgkosw]ke[\x2b\x2f-9w-z]))
```

## Log4Shell Detector (Python)

Python based scanner to detect the most obfuscated forms of the exploit codes. 

https://github.com/Neo23x0/log4shell-detector

## Find Log4j on Linux

```
ps aux | egrep '[l]og4j'
find / -iname "log4j*"
lsof | grep log4j
grep -r --include *.[wj]ar "JndiLookup.class" / 2>&1 | grep matches
```

## Find Vulnerable Log4j on Windows

```powershell 
gci 'C:\' -rec -force -include *.jar -ea 0 | foreach {select-string "JndiLookup.class" $_} | select -exp Path
```

by [@CyberRaiju](https://twitter.com/CyberRaiju/status/1469505677580124160)


## YARA

https://github.com/Neo23x0/signature-base/blob/master/yara/expl_log4j_cve_2021_44228.yar

## Help 

Please report findings that are not covered by these detection attempts.
# Using setup.py
<h1 align="center">
  <br>
  log4j-detect
</h1>

<h4 align="center">Simple Python 3 script to detect the "Log4j" Java library vulnerability (CVE-2021-44228) for a list of URL with multithreading</h4>

---

The script "log4j-detect.py" developed in Python 3 is responsible for detecting whether a list of URLs are vulnerable to CVE-2021-44228.

To do so, it sends a GET request using threads (higher performance) to each of the URLs in the specified list. The GET request contains a payload that on success returns a DNS request to Burp Collaborator / interactsh. This payload is sent in a test parameter and in the "User-Agent" / "Referer" / "X-Forwarded-For" / "Authentication" headers.
Finally, if a host is vulnerable, an identification number will appear in the subdomain prefix of the Burp Collaborator / interactsh payload and in the output of the script, allowing to know which host has responded via DNS.

It should be noted that this script only handles DNS detection of the vulnerability and does not test remote command execution.

### Downloading log4j-detect.py

```sh
wget https://github.com/takito1812/log4j-detect/raw/main/log4j-detect.py
```

### Running log4j-detect.py

```sh
python3 log4j-detect.py <urlFile> <collaboratorPayload>
```

![imagen](https://user-images.githubusercontent.com/56491288/145856295-f85b06da-17f2-4aa7-85fb-e0b75d6e1965.png)

