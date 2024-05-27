# GLSA-OVAL
GLSA-OVAL
[chat gpt4](https://chatgpt.com/)  tinkerage  this is early prototype ware ... "Think-ware" at present... 
and bit of testing and fiddeling 
and   [@Gentoo] (https://github.com/gentoo) Security Devs care to use for an infra toy   have at  it.. 

https://security.gentoo.org/  (at present no https://security.gentoo.org/oval/  but one can hope this might work enough in the future to bother...  ) and nested pages at https://security.gentoo.org/glsa/
https://nvd.nist.gov/vuln/detail/CVE-XXXX-XXXX  to were XXXX-XXXX  is replaced  to the reeal cve number and parsed over http/s into an OCAL file Hopefully ... 

## via , to mention but a few 
	"github.com/antchfx/htmlquery"
	"github.com/pandatix/go-cvss/31"
	"github.com/quay/goval-parser/oval"
	"github.com/umisama/go-cvss/v3"
	"github.com/PuerkitoBio/goquery"  and related items,,, ie go-sqlite 


#### 
https://oval.mitre.org/  or https://github.com/CISecurity/OVALRepo 
NIST Computer Security Division
The Security Content Automation Program (SCAP) is a public free repository of security content to be used for automating technical control compliance activities, vulnerability checking (both application misconfigurations and software flaws), and security measurement. Created January 2007.
Repository: http://scap.nist.gov/content/ 

ie Openscap , other vulscanners or automation  Vuls.io or Vuls repo webui also on guthub. https://www.mageni.net/  and likewise 
https://github.com/Admyral-Security/admyral one can pull in scans if one needs to do e-discovery / IR 

Debian , Redhat Etc.. already make oval XML DB files for Vulns , so I surmised a tool to scape the Gentoo GLSA to something a SCAP tool or SIEM might be able to cgew on might be some fun insomnia tinkerage... 

1) scape the Sec. Gentoo page/s  and NVD linked sub pages/articles   and output a OVAL form them  ( gits and shiggles oval in sqlite for vuls.io/vuls repo  as a quick n dirty shim ..) 
2)  which could be quite useful in an Enterprise setting using a Farm of mixed linux's Gentoo included... ie "Rackspace [.com] caliber of hosting firms
3)  or reserchers / Redteam uses whom need to evaluate  boxes more quickly.. in their developer Enviorments ...
4)  my motivation was to make more automated Systems Administration/ Cybersecurity of Gentoo Boxes eaier to keep secured/ automation of infra-security.. 
