"""Describe imported routing claims without attributing a person or trusting a forged hop."""
import ipaddress
import re


def trace_origin(email, ips):
    hops = []
    for index, header in enumerate(reversed(email.get('received', [])), 1):
        # Only the sending side of a Received field belongs to this hop's source.
        match = re.search(r'\bfrom\s+(.+?)(?=\s+by\s|;|$)', header, re.I | re.S)
        sending = match.group(1) if match else ''
        candidates = re.findall(r'[0-9a-fA-F:.]+', re.sub('IPv6:', '', sending, flags=re.I))
        public = []
        for candidate in candidates:
            try:
                address = ipaddress.ip_address(candidate)
                if address.is_global and str(address) not in public: public.append(str(address))
            except ValueError:
                pass
        receiver = re.search(r'\bby\s+([^\s;]+)', header, re.I)
        hops.append({'hop': index, 'claimed_from': sending or 'UNKNOWN', 'claimed_by': receiver.group(1) if receiver else 'UNKNOWN', 'public_ips': public, 'timestamp': header.rsplit(';', 1)[1].strip() if ';' in header else 'UNKNOWN', 'trust': 'UNVERIFIED imported header', 'evidence': header})
    earliest = next((h for h in hops if h['public_ips']), None)
    observed = earliest['public_ips'][0] if earliest else None
    detail = next((i for i in ips if i['ip'] == observed), {})
    claimed_client_ip = None
    client_ip_header = None
    for item in email.get('originating_ip_headers', []):
        for candidate in re.findall(r'(?<![\w:])(?:\d{1,3}\.){3}\d{1,3}(?![\w:])|[0-9a-fA-F]*:[0-9a-fA-F:]+', re.sub(r'IPv6:', '', item.get('value', ''), flags=re.I)):
            try:
                address = ipaddress.ip_address(candidate)
                if address.is_global:
                    claimed_client_ip = str(address)
                    client_ip_header = item.get('header')
                    break
            except ValueError:
                pass
        if claimed_client_ip:
            break
    client_detail = next((i for i in ips if i['ip'] == claimed_client_ip), {})
    client_area = ', '.join(str(value) for value in (client_detail.get('city'), client_detail.get('region'), client_detail.get('country')) if value) or 'UNKNOWN'
    client_status = 'PRESENT IN UNVERIFIED EMAIL HEADER' if claimed_client_ip else 'NOT PROVIDED BY EMAIL SERVICE'
    explanation = ('A claimed sender-device IP was found in an email header. Its network location is approximate; the header can be forged and a VPN or mobile carrier can obscure the person’s location.' if claimed_client_ip else 'The email service did not include the sender device public IP. The observed IP belongs to mail-delivery infrastructure, so the writer’s physical location cannot be determined from this email.')
    return {'status': 'OBSERVED / UNVERIFIED' if observed else 'UNKNOWN', 'earliest_observed_ip': observed, 'reliable_origin_ip': None, 'sender_device_ip': claimed_client_ip, 'sender_device_ip_header': client_ip_header, 'sender_device_ip_status': client_status, 'sender_location': client_area if claimed_client_ip else 'UNKNOWN', 'sender_location_status': 'APPROXIMATE CLIENT NETWORK / UNVERIFIED' if claimed_client_ip else 'NOT DETERMINED', 'country': detail.get('country'), 'region': detail.get('region'), 'city': detail.get('city'), 'asn': detail.get('asn'), 'organization': detail.get('organization'), 'source_hop': earliest['hop'] if earliest else None, 'hops': hops, 'explanation': explanation}
