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

def count_lookups_for_include(include_domain):
    count = 0
    spf_record = get_spf_record(include_domain)
    if spf_record:
        for part in spf_record.split():
            if any(part.startswith(mechanism) for mechanism in ["include:", "a:", "mx:", "ptr:", "exists:"]):
                count += 1
    return count

def flatten_spf(spf_record):
    flattened_record = []
    parts = spf_record.split()

    lookup_mechanisms = ["include:", "a:", "mx:", "ptr:", "exists:"]
    dns_lookup_count = sum(1 for part in parts if any(part.startswith(mechanism) for mechanism in lookup_mechanisms))

    # A dictionary to store include domains and their associated lookup counts
    include_lookup_counts = {part.split(':', 1)[1]: count_lookups_for_include(part.split(':', 1)[1]) for part in parts if part.startswith("include:")}

    # Sort the include domains by lookup counts in descending order
    sorted_includes = sorted(include_lookup_counts.keys(), key=lambda x: -include_lookup_counts[x])

    for part in parts:
        if part.startswith('include:') and dns_lookup_count > 3:
            if part.split(':', 1)[1] in sorted_includes:
                include_domain = part.split(':', 1)[1]
                include_spf = get_spf_record(include_domain)

                if include_spf:
                    for include_part in include_spf.split():
                        if include_part.startswith('ip4:') or include_part.startswith('ip6:'):
                            flattened_record.append(include_part)
                    dns_lookup_count -= include_lookup_counts[include_domain]
                    sorted_includes.remove(include_domain)  # So we don't process the same include again
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
