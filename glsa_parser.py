#!/usr/bin/python3
#
import requests 
import urllib3
# import  bs4 
from bs4 import BeautifulSoup
import re
from datetime import datetime
from vulnlist import VulnList, nvd

def generate_oval_xml(glsa_url, affected_packages, resolution_steps, cve_references, cvss_scores, oval_description):
    """
    Generate OVAL XML from provided security advisory details.
    """
    remediation_resolution = (
        f"Remediation/Resolution\n"
        f"{resolution_steps}"
    )
    
    # Append the remediation resolution to the oval description
    oval_description += f"\n{remediation_resolution}"
    
    cve_details = ""
    for cve_id in cve_references:
        vulnerability = nvd.get_vulnerability(cve_id)
        if vulnerability:
            cve_details += (
                f"<cve_details>\n"
                f"  <cve_id>{vulnerability.cve_id}</cve_id>\n"
                f"  <description>{vulnerability.description}</description>\n"
                f"  <cvss_score>{vulnerability.cvss_score}</cvss_score>\n"
                f"  <severity>{vulnerability.severity}</severity>\n"
                f"</cve_details>\n"
            )

    oval_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5">
  <metadata>
    <title>Gentoo GLSA {glsa_url}</title>
    <description>{oval_description}</description>
    <timestamp>{datetime.now().isoformat()}</timestamp>
  </metadata>
  <definition id="GLSA-{glsa_url.split('/')[-1]}" version="1">
    <metadata>
      <vendor>GENTOO_SECURITY_ADVISORY</vendor>
      <source>GLSA-{glsa_url.split('/')[-1]}</source>
    </metadata>
    <criteria>
      <criterion>
        <target>affected_packages</target>
        <condition>
          <test_ref>oval:com.gentoo:def:1</test_ref>
        </condition>
      </criterion>
    </criteria>
    <cve_references>
      {cve_details}
    </cve_references>
  </definition>
</oval_definitions>
"""
    return oval_xml

def save_oval_xml(oval_xml, filename='oval.xml'):
    """
    Save OVAL XML to a file.
    """
    with open(filename, 'w') as file:
        file.write(oval_xml)

def parse_glsa_page(glsa_page_url):
    """
    Parse a GLSA page for affected packages, resolution steps, and CVE references.
    """
    try:
        response = requests.get(glsa_page_url)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"Error fetching GLSA page: {e}")
        return None, None, None
    
    soup = BeautifulSoup(response.text, 'html.parser')

    # Parse affected packages
    vulnlist = VulnList()
    try:
        affected_packages = vulnlist.get_affected_packages(glsa_page_url)
    except Exception as e:
        print(f"Error retrieving affected packages for {glsa_page_url}: {e}")
        affected_packages = []

    # Parse resolution steps
    resolution_tag = soup.find('h3', text='Resolution')
    resolution_steps = ""
    if resolution_tag:
        resolution_steps = resolution_tag.find_next('pre').text.strip()

    # Parse CVE references
    cve_references = []
    references_tag = soup.find('h3', text='References')
    if references_tag:
        for li in references_tag.find_next('ul').find_all('li'):
            cve_url = li.find('a')['href']
            cve_id = cve_url.split('/')[-1]
            cve_references.append(cve_id)

    return affected_packages, resolution_steps, cve_references

def scrape_glsa():
    """
    Scrape GLSA page for security advisories and process them.
    """
    base_url = 'https://security.gentoo.org'
    glsa_url = base_url + '/glsa'

    try:
        response = requests.get(glsa_url)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"Error fetching GLSA page: {e}")
        return

    soup = BeautifulSoup(response.text, 'html.parser')
    glsa_links = soup.find_all('a', href=re.compile('/glsa/'))

    for link in glsa_links:
        glsa_page_url = base_url + link['href']
        affected_packages, resolution_steps, cve_references = parse_glsa_page(glsa_page_url)

        if affected_packages is None or resolution_steps is None or cve_references is None:
            continue

        print("Affected Packages:")
        for package in affected_packages:
            print(package)
        print("---")

        # Placeholder values for demonstration purposes
        cvss_scores = []
        oval_description = "Description of the vulnerability"

        oval_xml = generate_oval_xml(
            glsa_page_url,
            affected_packages,
            resolution_steps,
            cve_references,
            cvss_scores,
            oval_description
        )

        save_oval_xml(oval_xml)

if __name__ == '__main__':
    scrape_glsa()
