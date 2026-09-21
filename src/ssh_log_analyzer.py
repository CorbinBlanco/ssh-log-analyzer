import re
from datetime import datetime
from tkinter import Tk, filedialog



def bruteforce():

    fullSec = False

    # dictionaries that group failed and successful password logins by source IP
    attempts = {}
    succAttempts = {}

    # match failed password logins, including attempts using invalid usernames
    pattern = r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
    # match successful password logins
    patternA = r"Accepted password for (?:accepted user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"



    # lets user choose between a detailed report or a summary of possible breaches
    user = input("""
    Welcome to Corbins SSH Log Analyzer.
    Press 1 for a full security overview
    Press 2 for a short summarization:
    
    """)

    if user == "1":
        fullSec = True
        print("Current mode: Full security")
    elif user == "2":
        fullSec = False
        print("1Current mode: Short summarization")
    else:
        print("Please enter either 1 or 2")
        return


    # opens a file picker window that lets user choose what file they want to analyze
    root = Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    filePath = filedialog.askopenfilename(
        parent=root, title="Select a file to analyze", filetypes=[("Log files", "*.log"), ("Text files", "*.txt"), ("All Files", "*.*")]
    )

    root.destroy()

    if not filePath:
        print("File not found. Please try again")
        return

    # opens the file that user picked and scans each line for failed or successful authentications
    try:
        with open(rf"{filePath}", "r") as file:

            print("SECURITY OVERVIEW \n \n \n")

            for line in file:

                # searches the line for failed and successful password logins. A = accepted
                match = re.search(pattern, line)
                matchA = re.search(patternA, line)


                # for a failed login, extracts the username, source IP, port, and timestamp
                if match:
                    user = (match.group("user"))
                    ip = (match.group("ip"))
                    port = (match.group("port"))
                    dates = line[0:15]

                    # initializes tracking for this IP. using sets keep usernames and ports unique
                    if ip not in attempts:
                        attempts[ip] = {
                            "count": 0,
                            "users": set(),
                            "ports": set(),
                            "Dates & Times": []
                        }

                    attempts[ip]["count"] += 1
                    attempts[ip]["users"].add(user)
                    attempts[ip]["ports"].add(port)
                    attempts[ip]["Dates & Times"].append(dates)

                # for a successful login, extracts username, source IP, port, and timestamp
                if matchA:
                    userA = matchA.group("user")
                    ipA = matchA.group("ip")
                    portA = matchA.group("port")
                    datesA = line[0:15]

                    # stores successful login details for later comparison with failed attempts
                    if ipA not in succAttempts:
                        succAttempts[ipA] = {
                            "users": set(),
                            "ports": set(),
                            "Dates & Times": []
                        }
                    succAttempts[ipA]["users"].add(userA)
                    succAttempts[ipA]["ports"].add(portA)
                    succAttempts[ipA]["Dates & Times"].append(datesA)



    except FileNotFoundError:
        print("File not found. Please try again")
        return


    """Review the failed login records for each source IP.
        "ip" is the source IP address, and "info" contains its failure count,
        unique usernames, unique ports, and recorded timestamps.
        Full mode displays details for IPs with at least five failed logins.
        Both modes check whether these IPs also have successful logins
        and evaluate the timestamps to decide whether to display an alert."""

    for ip, info in attempts.items():

        # full mode, reports IPs with at least five failed password logins
        if info["count"] >= 5 and fullSec == True:
            user = ", ".join(info["users"])
            port = ", ".join(info["ports"])

            # sorts timestamps chronologically
            dates = sorted(info["Dates & Times"], key=lambda date: datetime.strptime(f"2026 {date}",
                                                                          "%Y %b %d %H:%M:%S"))

            print(f"""      
{info["count"]} brute force attempts from IP: {ip}
Usernames used: 
{user}
Ports used: 
{port}
First Date: {dates[0]}
Last Date: {dates[-1]}
                        """)


            # checks if this IP has repeated failures and also has successful logins
            if info["count"] >= 5 and ip in succAttempts:
                infoA = succAttempts[ip]

                user = ", ".join(sorted(info["users"]))
                port = ", ".join(sorted(info["ports"]))

                dates = sorted(
                    info["Dates & Times"], key=lambda date: datetime.strptime(f"2026 {date}",
                                                                              "%Y %b %d %H:%M:%S"))

                userA = ", ".join(sorted(infoA["users"]))
                portA = ", ".join(sorted(infoA["ports"]))

                datesA = sorted(
                    infoA["Dates & Times"], key=lambda date: datetime.strptime(f"2026 {date}",
                                                                               "%Y %b %d %H:%M:%S"))

                # compares the latest successful login timestamp (-1) with the third failed login timestamp (2)

                datesA[-1] = datetime.strptime(f"2026 {datesA[-1]}", "%Y %b %d %H:%M:%S")
                dates[2] = datetime.strptime(f"2026 {dates[2]}", "%Y %b %d %H:%M:%S")

                if datesA[-1] >= dates[2]:
                    print("INTERVENE IMMEDIATELY")
                    print(f"POSSIBLE SUCCESSFUL BRUTE FORCE LOGIN FROM IP: {ip}")

                    print(f"""
Failed attempts: {info["count"]}
Failed usernames: {user}
Successful usernames: {userA}
Failed ports: {port}
Successful ports: {portA}
First failed attempt: {dates[0]}
Last failed attempt: {dates[-1]}
Successful login time: {datesA[-1]}
                            """)









        # "short mode". Only evaluates IPs with repeated failures and successful logins
        if info["count"] >= 5 and ip in succAttempts and fullSec == False:
            infoA = succAttempts[ip]


            user = ", ".join(sorted(info["users"]))
            port = ", ".join(sorted(info["ports"]))

            dates = sorted(
                info["Dates & Times"],key=lambda date: datetime.strptime(f"2026 {date}",
                                                                         "%Y %b %d %H:%M:%S"))

            userA = ", ".join(sorted(infoA["users"]))
            portA = ", ".join(sorted(infoA["ports"]))

            datesA = sorted(
                infoA["Dates & Times"],key=lambda date: datetime.strptime(f"2026 {date}",
                                                                          "%Y %b %d %H:%M:%S"))

            datesA[-1] = datetime.strptime(f"2026 {datesA[-1]}", "%Y %b %d %H:%M:%S")
            dates[2] = datetime.strptime(f"2026 {dates[2]}", "%Y %b %d %H:%M:%S")

            if datesA[-1] >= dates[2]:
                print("INTERVENE IMMEDIATELY")
                print(f"POSSIBLE SUCCESSFUL BRUTE FORCE LOGIN FROM IP: {ip}")

                print(f"""
Failed attempts: {info["count"]}
Failed usernames: {user}
Successful usernames: {userA}
Failed ports: {port}
Successful ports: {portA}
First failed attempt: {dates[0]}
Last failed attempt: {dates[-1]}
Successful login time: {datesA[-1]}
                """)


bruteforce()
