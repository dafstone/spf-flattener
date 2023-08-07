import dns.resolver

def get_spf_record(domain):
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            for string in rdata.strings:
                if string.decode('utf-8').startswith('v=spf1'):
                    return string.decode('utf-8')
        return None
    except dns.exception.DNSException:
        return None

def flatten_spf(spf_record):
    flattened_record = []
    parts = spf_record.split()

    for part in parts:
        if part.startswith('include:'):
            include_domain = part.split(':', 1)[1]
            include_spf = get_spf_record(include_domain)

            if include_spf:
                for include_part in include_spf.split():
                    if include_part.startswith('ip4:') or include_part.startswith('ip6:'):
                        flattened_record.append(include_part)
        else:
            flattened_record.append(part)
            
    return ' '.join(flattened_record)

if __name__ == '__main__':
    domain = input("Enter the domain to fetch and flatten its SPF record: ")
    spf_record = get_spf_record(domain)
    
    if spf_record:
        print(f"Original SPF: {spf_record}")
        flattened_spf = flatten_spf(spf_record)
        print(f"Flattened SPF: {flattened_spf}")
    else:
        print(f"No SPF record found for {domain}.")
