import requests
from bs4 import BeautifulSoup
import re
from datetime import datetime
from vulnlist import VulnList

def generate_oval_xml(glsa_url, affected_packages, resolution_steps, cve_references, cvss_scores, oval_description):
    # ... (existing code remains the same)

def save_oval_xml(oval_xml):
    # ... (existing code remains the same)

def scrape_glsa():
    base_url = 'https://security.gentoo.org'
    glsa_url = base_url + '/glsa'

    response = requests.get(glsa_url)
    soup = BeautifulSoup(response.text, 'html.parser')

    glsa_links = soup.find_all('a', href=re.compile('/glsa/'))
    
    vulnlist = VulnList()
    
    for link in glsa_links:
        glsa_page_url = base_url + link['href']
        
        try:
            affected_packages = vulnlist.get_affected_packages(glsa_page_url)
        except Exception as e:
            print(f"Error retrieving affected packages for {glsa_page_url}: {str(e)}")
            affected_packages = []
        
        print("Affected Packages:")
        for package in affected_packages:
            print(package)
        print("---")
        
        # ... (rest of the code remains the same)
        
scrape_glsa()import requests
from bs4 import BeautifulSoup
import re
from datetime import datetime
from vulnlist import nvd

def generate_oval_xml(glsa_url, affected_packages, resolution_steps, cve_references, cvss_scores, oval_description):
    # ... (existing code remains the same)
    
    cve_details = ""
    for cve_id in cve_references:
        vulnerability = nvd.get_vulnerability(cve_id)
        if vulnerability:
            cve_details += f"<cve_details>\n"
            cve_details += f"  <cve_id>{vulnerability.cve_id}</cve_id>\n"
            cve_details += f"  <description>{vulnerability.description}</description>\n"
            cve_details += f"  <cvss_score>{vulnerability.cvss_score}</cvss_score>\n"
            cve_details += f"  <severity>{vulnerability.severity}</severity>\n"
            cve_details += f"</cve_details>\n"
    
    oval_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5">
  <!-- ... (existing XML structure remains the same) -->
  <cve_references>
    {cve_references}
  </cve_references>
  <cve_details>
    {cve_details}
  </cve_details>
  <!-- ... (remaining XML structure remains the same) -->
</oval_definitions>
"""
    return oval_xml

import requests
from bs4 import BeautifulSoup
import re
from datetime import datetime
from vulnlist import nvd

def generate_oval_xml(glsa_url, affected_packages, resolution_steps, cve_references, cvss_scores, oval_description):
    # ... (existing code remains the same)
    
    cve_details = ""
    for cve_id in cve_references:
        vulnerability = nvd.get_vulnerability(cve_id)
        if vulnerability:
            cve_details += f"<cve_details>\n"
            cve_details += f"  <cve_id>{vulnerability.cve_id}</cve_id>\n"
            cve_details += f"  <description>{vulnerability.description}</description>\n"
            cve_details += f"  <cvss_score>{vulnerability.cvss_score}</cvss_score>\n"
            cve_details += f"  <severity>{vulnerability.severity}</severity>\n"
            cve_details += f"</cve_details>\n"
    
    oval_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5">
  <!-- ... (existing XML structure remains the same) -->
  <cve_references>
    {cve_references}
  </cve_references>
  <cve_details>
    {cve_details}
  </cve_details>
  <!-- ... (remaining XML structure remains the same) -->
</oval_definitions>
"""
    return oval_xml

# ... (rest of the code remains the same)