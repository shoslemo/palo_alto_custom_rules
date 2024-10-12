import requests
import re
from bs4 import BeautifulSoup
import os

# Disable SSL warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Valid severity levels
VALID_SEVERITY = ['informational', 'low', 'medium', 'high', 'critical']

# Function to sanitize names by removing special characters
def sanitize_name(name):
    return re.sub(r'[^a-zA-Z0-9_ ]', '', name)

# Function to convert Suricata rule to Palo Alto rule
def convert_suricata_to_palo_alto(suricata_rule, rule_id):
    try:
        match = re.match(r'alert (.+?) (.+?) (.+?) \((.+?)\)', suricata_rule)
        if not match:
            return None, None
        action, proto, src_dest, details = match.groups()
        try:
            src_ip, dst_ip_port = re.split(r'\s+->\s+', src_dest)
        except ValueError:
            return None, None
        dst_ip_port_split = dst_ip_port.split(' ')
        dst_ip = dst_ip_port_split[0] if len(dst_ip_port_split) > 0 else 'any'
        dst_port = dst_ip_port_split[1] if len(dst_ip_port_split) > 1 else '80'
        src_ip = re.sub(r'\$[A-Z_]+', 'any', src_ip)
        dst_ip = re.sub(r'\$[A-Z_]+', 'any', dst_ip)
        dst_port = re.sub(r'\$[A-Z_]+', '80', dst_port)
        if not dst_port.isdigit():
            dst_port = '80'
        dst_port = dst_port.lstrip('0')
        details_dict = {key_value.split(':')[0].strip(): key_value.split(':')[1].strip() for key_value in details.split(';') if ':' in key_value}
        rule_id = sanitize_name(str(rule_id))
        threat_name = sanitize_name(details_dict.get('msg', f'Converted Rule {rule_id}').replace('"', ''))
        rule = f'<entry name="{rule_id}">\n'
        # Add signature if pattern exists
        pattern = details_dict.get('content', '').replace('|', ' ')
        if pattern:
            context = details_dict.get('context', 'tcp-context-free')
            negate = details_dict.get('negate', 'no')
            rule += f'''
                <signature>
                    <standard>
                        <entry name="test">
                            <and-condition>
                                <entry name="And Condition 1">
                                    <or-condition>
                                        <entry name="Or Condition 1">
                                            <operator>
                                                <pattern-match>
                                                    <pattern>{pattern}</pattern>
                                                    <context>{context}</context>
                                                    <negate>{negate}</negate>
                                                </pattern-match>
                                            </operator>
                                        </entry>
                                    </or-condition>
                                </entry>
                            </and-condition>
                            <order-free>no</order-free>
                            <scope>protocol-data-unit</scope>
                        </entry>
                    </standard>
                </signature>\n'''
        # Add threat name
        rule += f'<threatname>{threat_name}</threatname>\n'
        # Add severity
        severity = details_dict.get('classtype', 'informational')
        if severity not in VALID_SEVERITY:
            severity = 'informational'
        rule += f'<severity>{severity}</severity>\n'
        # Add direction
        direction = details_dict.get('direction', 'both')
        rule += f'<direction>{direction}</direction>\n'
        # Add affected host
        affected_host = details_dict.get('affected-host', 'client')
        rule += f'<affected-host>\n<{affected_host}>yes</{affected_host}>\n</affected-host>\n'
        # Add optional fields
        optional_fields = ['cve', 'reference', 'vendor', 'bugtraq']
        for field in optional_fields:
            value = details_dict.get(field, None)
            if value:
                rule += f'<{field}>\n<member>{value}</member>\n</{field}>\n'
        rule += '</entry>'
        return rule.strip(), threat_name
    except Exception as e:
        print(f"Error converting rule: {e}")
        return None, None

# Function to determine if a rule contains lots of IP addresses
def contains_lots_of_ips(rule):
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    ips = ip_pattern.findall(rule)
    return len(ips) > 10  # Example threshold

# Main script logic
def main():
    repository_url = input("Enter the URL of the rules repository (or press Enter to use the default Threatvault): ")
    if not repository_url:
        repository_url = "https://rules.emergingthreats.net/open/suricata/rules/"

    enforce_ip_check = input("Enforce lots of IP addresses check? This function does not currently work as intended, recommend no. (yes/no): ").strip().lower() == "yes"
    
    num_rules = input("How many rules should be grabbed (or 'all' for all rules): ").strip().lower()
    if num_rules != "all":
        num_rules = int(num_rules)
    
    rule_id_start = int(input("Enter the starting rule ID (41000 is the most common value): ").strip())
    
    # Fetch the webpage
    response = requests.get(repository_url, verify=False)
    soup = BeautifulSoup(response.content, 'html.parser')

    # Find all rule links
    rule_links = [a['href'] for a in soup.find_all('a', href=True) if a['href'].endswith('.rules')]

    # Collect converted rules
    rule_id = rule_id_start
    rule_count = 0
    os.makedirs('output', exist_ok=True)
    for link in rule_links:
        if num_rules != "all" and rule_count >= num_rules:
            break
        rule_url = repository_url + link
        rule_response = requests.get(rule_url, verify=False)
        rule_content = rule_response.text
        for rule in rule_content.split('\n'):
            if num_rules != "all" and rule_count >= num_rules:
                break
            if enforce_ip_check and contains_lots_of_ips(rule):
                continue
            converted_rule, threat_name = convert_suricata_to_palo_alto(rule, rule_id)
            if converted_rule:
                filename = f'output/palo_alto_rule_{rule_id}_{threat_name}.xml'
                with open(filename, 'w') as f:
                    f.write('<?xml version="1.0"?>\n')
                    f.write('<vulnerability-threats>\n')
                    f.write(f'<vulnerability-threat version="10.1.0">\n{converted_rule}\n</vulnerability-threat>\n')
                    f.write('</vulnerability-threats>\n')
                rule_id += 1
                rule_count += 1

    print("Conversion complete. Each rule is written to its own XML file in the 'output' folder")

if __name__ == "__main__":
    main()
