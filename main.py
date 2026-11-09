import argparse
import dns.exception
import dns.query
import dns.resolver
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

def attempt_zone_transfer(nameserver, domain):
    """
    Attempts one zone transfer.

    Returns:
        True if the transfer succeeded (zone data is printed), the
        string "refused" if the server definitively refused the
        transfer or returned a malformed or empty answer, or None if
        the attempt was inconclusive (timeout or unexpected error), so
        it is no evidence either way about the zone.
    """
    try:
        zone = dns.zone.from_xfr(dns.query.xfr(nameserver, domain, timeout=10))
        print(f"Zone transfer successful from {nameserver} for domain {domain}:")
        for name, rdataset in zone.nodes.items():
            print(f"{name} {rdataset}")
        return True
    except dns.exception.FormError:
        logging.warning("Zone transfer failed from %s for %s (FormError).", nameserver, domain)
        return "refused"
    except dns.query.TransferError as e:
        logging.warning("Zone transfer failed from %s for %s: %s", nameserver, domain, e)
        return "refused"
    except (TimeoutError, dns.exception.Timeout):
        logging.warning("Timeout during zone transfer from %s for %s.", nameserver, domain)
        return None
    except Exception as e:
        logging.error("An unexpected error occurred during zone transfer from %s for %s: %s", nameserver, domain, e)
        return None

def check_zone_transfer(domain, nameserver=None):
    """
    Attempts to perform a DNS zone transfer from the specified nameserver.

    Args:
        domain (str): The domain to check.
        nameserver (str, optional): The nameserver to query. If None, attempt to auto-discover nameservers.

    Returns:
        bool: True if a zone transfer is successful, False if at least
        one nameserver definitively refused the transfer and none
        succeeded, or None if the check could not reach a verdict:
        nameserver discovery failed, or every transfer attempt timed
        out or errored. A timeout is not evidence that a zone is
        protected, so it never produces the False verdict.
    """

    try:
        if nameserver is None:
            # Attempt to discover nameservers using DNS queries.
            # Discovery goes through the configured resolver, so in a
            # split horizon setup the discovered set is the set that
            # resolver can see.
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

            saw_refusal = False
            for ns in nameservers:
                outcome = attempt_zone_transfer(ns, domain)
                if outcome is True:
                    return True  # Zone transfer succeeded, no need to try other nameservers
                if outcome == "refused":
                    saw_refusal = True
            # False only when at least one server actually refused.
            # If every attempt timed out or errored, there is no verdict.
            return False if saw_refusal else None
        else:
            # Perform zone transfer using specified nameserver
            outcome = attempt_zone_transfer(nameserver, domain)
            if outcome is True:
                return True
            if outcome == "refused":
                return False
            return None

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
        print(f"Zone transfer check could not reach a verdict for {domain}: nameserver discovery failed or every transfer attempt timed out or errored, so no verdict could be made.")
        sys.exit(1)
    if result:
        logging.info("Zone transfer vulnerability found for %s.", domain)
    else:
        logging.info("Zone transfer vulnerability not found for %s.", domain)


if __name__ == "__main__":
    main()

# Usage Examples:
# 1. Check for zone transfer vulnerability for example.com, automatically determining the nameserver:
#    python3 main.py example.com
#
# 2. Check for zone transfer vulnerability for example.com, using a specific nameserver:
#    python3 main.py example.com ns1.example.com
