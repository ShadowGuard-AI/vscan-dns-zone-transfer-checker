import argparse
import dns.query
import dns.zone
import logging
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the command-line argument parser.

    Returns:
        argparse.ArgumentParser: The argument parser object.
    """
    parser = argparse.ArgumentParser(description="Detects DNS zone transfer vulnerabilities.")
    parser.add_argument("domain", help="The domain to check for zone transfer vulnerability.")
    parser.add_argument("nameserver", nargs='?', default=None, help="The nameserver to query. If not provided, the script will attempt to find the domain's nameservers automatically.")
    return parser

def check_zone_transfer(domain, nameserver=None):
    """
    Attempts to perform a DNS zone transfer from the specified nameserver.

    Args:
        domain (str): The domain to check.
        nameserver (str, optional): The nameserver to query. If None, attempt to auto-discover nameservers.

    Returns:
        bool: True if a zone transfer is successful, False if the check
        completed and the transfer was refused or empty, or None if
        nameserver discovery failed and the check could not run.
    """

    try:
        if nameserver is None:
            # Attempt to discover nameservers using DNS queries
            # Discovery goes through the system resolver and its
            # recursive servers, not the domain's own authoritative
            # servers, so a split horizon setup can hand back a set of
            # nameservers an outside checker would never see, or miss
            # the ones it would.
            try:
                nameserver_answers = dns.resolver.resolve(domain, 'NS')
                nameservers = [str(rdata.target) for rdata in nameserver_answers]
                if not nameservers:
                    logging.error("Could not automatically determine nameservers for %s.", domain)
                    return None
                logging.info("Automatically discovered nameservers: %s", nameservers)
            except dns.resolver.NXDOMAIN:
                logging.error("Domain %s does not exist.", domain)
                return None
            except dns.resolver.Timeout:
                logging.error("DNS query timeout while resolving nameservers for %s.", domain)
                return None
            except Exception as e:
                logging.error("Error resolving nameservers for %s: %s", domain, e)
                return None

            for ns in nameservers:
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=10))
                    print(f"Zone transfer successful from {ns} for domain {domain}:")
                    for name, rdataset in zone.nodes.items():
                        print(f"{name} {rdataset}")
                    return True  # Zone transfer succeeded, no need to try other nameservers
                except dns.exception.FormError:
                    logging.warning("Zone transfer failed from %s for %s (FormError).", ns, domain)
                except dns.query.TransferError as e:
                    logging.warning("Zone transfer failed from %s for %s: %s", ns, domain, e)
                except TimeoutError:
                    logging.warning("Timeout during zone transfer from %s for %s.", ns, domain)
                except Exception as e:
                    logging.error("An unexpected error occurred during zone transfer from %s for %s: %s", ns, domain, e)
        else:
            # Perform zone transfer using specified nameserver
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(nameserver, domain, timeout=10))
                print(f"Zone transfer successful from {nameserver} for domain {domain}:")
                for name, rdataset in zone.nodes.items():
                    print(f"{name} {rdataset}")
                return True
            except dns.exception.FormError:
                logging.warning("Zone transfer failed from %s for %s (FormError).", nameserver, domain)
            except dns.query.TransferError as e:
                logging.warning("Zone transfer failed from %s for %s: %s", nameserver, domain, e)
            except TimeoutError:
                logging.warning("Timeout during zone transfer from %s for %s.", nameserver, domain)
            except Exception as e:
                logging.error("An unexpected error occurred during zone transfer from %s for %s: %s", nameserver, domain, e)

        # Every failure above lands here as one False, including a
        # timeout from every nameserver. A network that silently drops
        # the transfer and a server that refuses it produce the same
        # "not found" verdict in main, though only one of them is
        # actually evidence the zone is protected.
        return False  # Zone transfer failed from all nameservers.

    except Exception as e:
        logging.error("An error occurred: %s", e)
        return None


def main():
    """
    Main function to execute the DNS zone transfer checker.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    domain = args.domain
    nameserver = args.nameserver

    # Input validation
    if not domain:
        logging.error("Domain cannot be empty.")
        sys.exit(1)

    logging.info("Starting DNS zone transfer check for %s...", domain)

    result = check_zone_transfer(domain, nameserver)
    if result is None:
        print(f"Nameserver discovery failed for {domain}: the zone transfer check could not run, so no verdict could be made.")
        sys.exit(1)
    if result:
        logging.info("Zone transfer vulnerability found for %s.", domain)
    else:
        logging.info("Zone transfer vulnerability not found for %s.", domain)


if __name__ == "__main__":
    main()

# Usage Examples:
# 1. Check for zone transfer vulnerability for example.com, automatically determining the nameserver:
#    python vscan-dns-zone-transfer-checker.py example.com
#
# 2. Check for zone transfer vulnerability for example.com, using a specific nameserver:
#    python vscan-dns-zone-transfer-checker.py example.com ns1.example.com
#
# Offensive Tools Integration:
#   This script can be integrated into a larger security audit framework or penetration testing tool.
#   It can be chained with other vulnerability scanners to provide a comprehensive assessment.
#   The logging output can be parsed to automatically identify vulnerable domains.