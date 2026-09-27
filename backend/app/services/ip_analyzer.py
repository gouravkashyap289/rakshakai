import os
from .network import public_ip

def analyze_ips(ips, domains):
    sources={ip:{'Email headers / body / URLs'} for ip in ips if public_ip(ip)}
    for domain in domains:
        for kind in ('A','AAAA'):
            for ip in domain.get('dns',{}).get(kind,{}).get('values',[]):
                if public_ip(ip): sources.setdefault(ip,set()).add('DNS: '+domain['domain'])
    result=[]
    for ip in sorted(sources)[:80]:
        row={'ip':ip,'source':sorted(sources[ip]),'status':'DATA NOT AVAILABLE','country':None,'region':None,'city':None,'latitude':None,'longitude':None,'asn':None,'organization':None,'isp':None,'hosting_provider':None,'datacenter':'UNKNOWN','vpn':'UNKNOWN','proxy':'UNKNOWN','tor':'UNKNOWN','risk':'Unverified','location_label':'Observed Infrastructure Location','location_limitation':'Approximate infrastructure geolocation; does not identify a sender or person.'}
        for kind,env in [('city','GEOLITE2_CITY_PATH'),('asn','GEOLITE2_ASN_PATH')]:
            if not os.getenv(env): continue
            try:
                import geoip2.database
                with geoip2.database.Reader(os.environ[env]) as reader:
                    data=getattr(reader,kind)(ip)
                    if kind=='city': row.update(country=data.country.name,region=data.subdivisions.most_specific.name,city=data.city.name,latitude=data.location.latitude,longitude=data.location.longitude,accuracy_radius_km=data.location.accuracy_radius)
                    else: row.update(asn=data.autonomous_system_number,organization=data.autonomous_system_organization)
                    row['status']='AVAILABLE'; row[kind+'_source']='Local MaxMind GeoLite2 database'
            except Exception: row[kind+'_status']='LOOKUP FAILED'
        result.append(row)
    return result
