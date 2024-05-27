# GLSA-OVAL

**GLSA-OVAL** is an early prototype aimed at generating OVAL (Open Vulnerability and Assessment Language) files from Gentoo Linux Security Advisories (GLSAs) and related vulnerability information.

**Note:** This is a work in progress, and should be considered "Think-ware" at present, with ongoing testing and fiddling.  ChatGPT has had a very useful hand in Rappid prototyping this.. 

The Gentoo Security team is welcome to use this as an infrastructure toy. some day ? or feel free to fork it ... 
BSD LIC to do WTF ever YOu want to with this. 

## Links

- [Gentoo Security Advisories](https://security.gentoo.org/) (Currently no https://security.gentoo.org/oval/, but one can hope this might work enough in the future to warrant it.)
- [Nested pages at https://security.gentoo.org/glsa/](https://security.gentoo.org/glsa/)
- [NVD Vulnerability Details](https://nvd.nist.gov/vuln/detail/CVE-XXXX-XXXX) (Replace "XXXX-XXXX" with the actual CVE number, which will be parsed over HTTP/S into an OVAL file, hopefully.)

## Dependencies

This project utilizes the following Go packages, among others:

- "github.com/antchfx/htmlquery"
- "github.com/pandatix/go-cvss/31"
- "github.com/quay/goval-parser/oval"
- "github.com/umisama/go-cvss/v3"
- "github.com/PuerkitoBio/goquery"

Additionally, it may integrate with go-sqlite for database operations.

## Background

- [OVAL Repository](https://oval.mitre.org/) or [OVALRepo](https://github.com/CISecurity/OVALRepo)
- [NIST Computer Security Division](https://csrc.nist.gov/)
- The [Security Content Automation Program (SCAP)](http://scap.nist.gov/content/) is a public, free repository of security content for automating technical control compliance activities, vulnerability checking (both application misconfigurations and software flaws), and security measurement. Created in January 2007.

This project aims to integrate with tools like [Openscap](https://www.open-scap.org/), other vulnerability scanners, or automation tools like [Vuls.io](https://vuls.io/), [Vuls Repo WebUI](https://github.com/future-architect/vuls), [Mageni](https://www.mageni.net/),  Likewise avlible as Code on Github.... 
[Admyral](https://github.com/Admyral-Security/admyral) (for e-discovery/IR), and others. or simular.. FOSS tools. 

## Motivation

1. Scrape the Gentoo Security pages and NVD-linked subpages/articles, and output OVAL data from them (potentially storing OVAL in SQLite for use with Vuls.io/Vuls Repo as a quick and dirty shim).
2. Provide a useful tool in an enterprise setting with a mixed Linux environment, including Gentoo (e.g., Rackspace-caliber hosting firms).
3. Aid researchers/red teams who need to evaluate boxes more quickly in their development environments.
4. Facilitate automated Systems Administration and Cybersecurity for Gentoo boxes, making it easier to keep them secured and automate infrastructure security.
5.   in time the tool could be handed over to Gentoo and they can make OVAL files on an more automatic Basis ...
6.   I USE github.com/pentoo overlay and Gentoo Linux often for Infra/Sec reserch , Home lab ettc.... Even google uses Gentoo's bits to make Chrome-OS ... because its flexable. 
