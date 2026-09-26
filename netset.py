print("NetSet  is RUNNING...")
import socket 
from datetime import datetime
common_ports = {
    21:"FTP",
    22:"SSH",
    23:"Telnet",
    25:"SMTP",
    53:"DNS",
    80:"HTTP",
    110:"POP3",
    143:"IMAP",
    443:"HTTPS",
    445:"SMB",
    3306:"MySQL",
    3389:"RDP",
    5432:"PostgreSQL",
    8080:"HTTP-Alt"
}
risk_levels = {
    21:"MEDIUM",
    23:"HIGH",
    445:"HIGH",
    3306:"HIGH",
    3389:"HIGH",
    22:"LOW",
    80:"MEDIUM",
    443:"LOW",
    8080:"MEDIUM"
}
def show_banner():
    print("NETSET")
    print()
def resolve_target(target):
    try:
        ip_address = socket.gethostbyname(target)
        return ip_address
    except socket.gaierror:
        return None
def scan_port(ip_address, port):
    sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    sock.settimeout(0.5)
    try:
        result = sock.connect_ex((ip_address, port))
        if result == 0:
            return True
        return False
    except socket.error:
        return False
    finally:
        sock.close()
def get_service_name(port):
    if port in common_ports:
        return common_ports[port]
    return "Unknown"
def get_risk_level(port):
    if port in risk_levels:
        return risk_levels[port]
    return "INFO"
def scan_target(ip_address):
    results=[]
    print("Starting scan...")
    print()
    for port in common_ports:
        service = get_service_name(port)
        print(f"Checking port {port}({service})...")
        is_open = scan_port(ip_address, port)
        if is_open:
            risk = get_risk_level(port)
            results.append({
                "port":port,
                "service":service,
                "risk":risk
            })
    return results
def display_results(results, target,ip_address):
    print()
    print("NetSet REPORT")
    print("Target:{target}")
    print(f"IP address:{ip_address}")
    print("Scan time:",
          datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )
    print()
    if not results:
        print("No open common ports were detected")
        print()
        return
    print("PORT      SERVICE        RISK")
    print("-" * 35)
    for result in results:
        print(f"{result['port']: <10}"
              f"{result['service']: <15}"
              f"{result['risk']: <10}"
        )
def show_security_summary(results):
    print()
    print("SECURITY SUMMARY")
    high_risk=0
    medium_risk=0
    low_risk=0
    for result in results:
        if result["risk"]=="HIGH":
            high_risk +=1
        elif result["risk"]=="MEDIUM":
            medium_risk +=1
        elif result["risk"]=="LOW":
            low_risk +=1
    print("High-risk services:",high_risk)
    print("Medium-risk services:",medium_risk)
    print("Low-risk services:",low_risk)
    print()
    if high_risk>0:
        print("WARNING:")
        print("Potentially risky service detected")
        print("Review whether these services need to be exposed")
    else:
        print("No high-risk services detected")
    print()
def main():
    show_banner()
    target= input("Enter an authorized target IP or hostname:").strip()
    if not target:
        print("ERROR")
        return
    print()
    print("RESOLVING....")
    ip_address = resolve_target(target)
    if ip_address is None:
        print("ERROR")
        return
    print(f"Target resolved to:{ip_address}")
    print()
    results = scan_target(ip_address)
    display_results(
        results,
        target,
        ip_address
    )
    show_security_summary(results)
    print("SCAN COMPLETE")
main()