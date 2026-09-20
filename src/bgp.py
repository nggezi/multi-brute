import requests

# 开关：True = 所有 ASN 的前缀合并写入一个文件；False = 每个 ASN 单独一个文件
MERGE_INTO_ONE = True
OUTPUT_FILE = 'prefixes.txt'


def get_prefixes(asn):
    url = f'https://bgp.he.net/super-lg/report/api/v1/prefixes/originated/{asn}'
    response = requests.get(url, timeout=15)

    if response.status_code == 200:
        data = response.json()
        # 过滤掉IPv6的前缀，只保留IPv4的前缀
        ipv4_prefixes = [item['Prefix'] for item in data['prefixes'] if ':' not in item['Prefix']]
        return ipv4_prefixes
    else:
        print(f"Failed to retrieve data for ASN {asn}. Status code: {response.status_code}")
        return []


def save_prefixes_to_file(prefixes, filename):
    # 每行一个前缀
    prefixes_line = '\n'.join(prefixes)
    with open(filename, 'w', encoding='utf-8') as file:
        file.write(prefixes_line)


def normalize_asn(asn):
    # 去掉可能的 "AS" 前缀
    asn = asn.strip().upper()
    if asn.startswith('AS'):
        asn = asn[2:]
    return asn


if __name__ == "__main__":
    # 询问用户输入ASN，支持多个（空格或逗号分隔）
    raw = input("Please enter the ASN(s), separated by space or comma: ")
    asns = [normalize_asn(a) for a in raw.replace(',', ' ').split() if a.strip()]

    if MERGE_INTO_ONE:
        merged = []
        for asn in asns:
            prefixes = get_prefixes(asn)
            if prefixes:
                merged.extend(prefixes)
                print(f"ASN {asn}: got {len(prefixes)} IPv4 prefixes")
            else:
                print(f"No prefixes found or failed to retrieve data for ASN {asn}.")

        if merged:
            save_prefixes_to_file(merged, OUTPUT_FILE)
            print(f"All {len(merged)} IPv4 prefixes have been saved to {OUTPUT_FILE}")
        else:
            print("No prefixes found.")
    else:
        for asn in asns:
            prefixes = get_prefixes(asn)
            if prefixes:
                filename = f'prefixes_{asn}.txt'
                save_prefixes_to_file(prefixes, filename)
                print(f"IPv4 prefixes for ASN {asn} have been saved to {filename} ({len(prefixes)} prefixes)")
            else:
                print(f"No prefixes found or failed to retrieve data for ASN {asn}.")
