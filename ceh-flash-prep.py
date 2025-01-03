import random

concepts = {
    "Basics":[
        "Info Sec",
        #Protecting info from unauthorized access, use, disclosure, disruption, modification, or destruction (think CIA TRIAD, the holy trinity of info sec)
        "Confidentiality",
        #Access only for those authorized to have access
        #No peeking, Karen!
        "Integrity",
        #Maintains accuracy and consistency of data
        "Availability",
        #Data is available when you need it
        "Authentication",
        #Verifying the identity of users
        #Who are you? Prove it!
        "Accountability",
        #Loggin and monitorin user actions for traceability, logs don't lie
        #AKA We're watching, always watching
        "Non-repudiation",
        #Prevents denial of actions
        #Can't say, "It Wasn't Me" Shaggy style
        "5 Classifications of Attack",
        #Passive, Active, Insider, Close-in, Distribution
        "Passive Attack",
        #No direct interaction, no altering the system or data, remaining undetected
        #This is the stalker nerd of cyberattacks lurking in the shadows, watching, listening, just creepin around
        #Eavesdropping, traffic analysis, and sniffing are its jam
        "Active Attack",
        #Direct interaction, loud, messy, very noticable, like a cyber-bull in a china shop
        #DoS, Malware....
        "Insider Attack",
        #Perpetrated by authorized users, like Todd from HR, who's been holding a grudge because I keep eating his yogurt
        "Close-in Attack",
        #External adversaries and wannabe hackers sliding into your DMs phishin' ya and exploitin' ya
        "Distribution Attack",
        "Categories of Info War",
        #Offsensive: Cyber smackdowns, disruptin', disablin' and destroyin' adversary opertions
        #Defensive: Cyber karate, protectin' and defendin' your systems
        #Psychological: Mind games. Using info to influence, confuse, and deceive public opinion and morale
        #Cyber espionage: Spying, stealin' secrets, and gatherin' intel. High-tech sneaky-peeky
        #Propaganda: Fake news, digital and global. Spreading lies and misinformation
        "CEH Methodology",
        #Recon: Stalker mode, on. 
        #Scanning: Poke and prod to find live hosts, open ports, services, and vulnerabilities
        #Gaining Access: Kickin down that digital door, like cyber SWAT
        #Maintaining Access: Establish persistence. Come in the backdoor, move in, rearrange the furniture, leave your toothbrush
        #Covering Tracks: Be a ghost, they don't have fingerprints.
        "Cyber Kill Chain Methodology Phases",
        #Recon, Weaponization, Delivery, Exploitation, Installation, Command and Control(C2, C&C), Actions on Objectives
        #Weaponization: Build-a-bomb, but cyber style
        #Delivery: Knock, Knock, it's payload o'clock
        #Exploitation: Activating Gotcha' mode
        #Installation: Sets up camp like mi casa su casa
        #C2: Enabling remote access/control. Dance, puppet, dance!
        #Actions on Objectives: Achieving the goal. 
        "TTPs",
        #Tactics, Techniques, Procedures
        #Tactics: Big picture, the plan, the strategy. High level descriptions of adversay behavior
        #Techniques: The how to, the method to achieve your goals, like phishing or a sending malicious cat meme
        #Procedures: Step by step execution. step 1, step 2, step 3, profit
        #TTPs are like the recipe for a cyberattack, the ingredients, the steps, and the final product
        #Knowing your enemy is half the battle
        "Adversary Behavorial Identification",
        "Indicators of Compromise",
        "Mitre Att&Ck Framework",
        "Diamond Model of Intrusion Analysis and Elements",
        "Information Assurance",
        "Defense in Depth",
        "Continual/Adaptive Securrity Strategy",
        "Threat Intelligence Lifecycle"
    ],
    "Laws":[
        "PCI DSS", 
        #It’s like the bodyguard for payment data, making sure companies don’t treat your credit card numbers like soggy Taco Bell receipts. 
        #If you’re storing credit info like a psycho, this is the “Hey, you gotta stop that” protocol.
        "ISO/IEC 27001:2013",
        #International gold star for olks who keps secrets
        "HIPPA",
        #Hospitals and clinics have to keep your records under wraps—or else! 
        "SOX",
        #Tattletale mechanism for keeping execs honest about their bank statements
        #Made for catching number-fudgers and protecting shareholders and the public from accounting errors and fraudulent pracices, primarily in publicly traded companies
        "DMCA",
        #DMCA’s the law that says, “Hey, quit pirating,” but all it does is make pirates more creative.
        #Download comes with a “cease and desist” letter. 
        "FISMA",
        #Don't Mess With Uncle Sam's Computer Files Act
        #All about keeping federal information systems and safeguard data handled by federal agencies and their contractors safer than the recipe for Coca-Cola
        "GDPR",
        #EU saying we know what you're up to Google and we're not having it.
        #Gives users right to be forgotten, and breaches should be reported before you can finish saying 'oops'(72 hours)  
        "DPA 2018"
        #GDPR but with extra British flair for post-Brexit life
    ],
    "Port and Portocols":[
        "Well-Known Ports",
        #0-1023
        #Celebrity ports, the A-listers, the famous protocols
        "Registered Ports",
        #1024-49151
        #Middle children of the port family, important but nobody is making them famous by any means
        "Dynamic Ports",
        #49152-65535
        #Temporary ports used for server communication, these are like the one-night stands of the port world, here today, gone tomorrow, don't even remember their names
        "FTP (Data Transer)",
        #File Transfer Protocol, 20
        #Transfers files between a client and server
        "FTP (Control Commands)",
        #File Transfer Protocol, 21
        #Sends commands for file transfers
        #It's like the bossy older sibling of port 20, telling it what to do
        "SSH/SCP/SFTP",
        #Secure Shell for remote access and file transfer, 22
        "Telnet",
        #Unsecure remote access, 23
        "SMTP",
        #Simple Mail Transfer Protocol, 25
        #Sends emails between servers
        "DNS",
        #Domain Name System, 53
        #Converts domain anmes to IP addresses because we're too dumb to remember numbers
        "DHCP",
        #Dynamic Host Configuration Protocol, 67-68
        #Assigns IP addresses dynamically on a network
        #You get an IP! And you get an IP!
        "TFTP",
        #Trivial File Transfer Protocol, 69
        "HTTP",
        #Hypertext Transfer Protocol, 80
        #Delivers websites to the people, probably the reason you're reading this right now
        "POP3",
        #Post Office Protocol version 3, 110
        #Retrieves emails you'll ignore from a server 
        "NTP",
        #Network Time Protocol, 123
        #Keeps all devices in syncy-sync, because time is important, and definitely not a social construct
        "RPC/DCOM",
        #Remote Procedure Call, 135
        #Manages remote procedure calls
        "NetBios",
        #Network Basic Input/Output System, 137-139
        #Basic netwrorking for Windows
        "IMAP",
        #Internet Message Access Protocol, 143
        #Lets you read emails without downloading them
        "SNMP",
        #Simple Network Management Protocol, 161
        #Keeps an eye on network devices like a nosy little neighbor
        "LDAP",
        #Lightweight Directory Access Protocol, 389
        #Someones gotta manages user directories, LDAP does
        "HTTPS",
        #Hypertext Transfer Protocol Secure, 443
        #Secured HTTP
        #HTTP but better dressed and concerned about security
        "SMB",
        #Server Message Block, 445
        #Shares files and printers
        #The office workhorse
        "Syslog",
        #System Logging Protocol, 514
        #Collects system logs from devices
        "SMTP (Secure)",
        #Simple Mail Transfer Protocol, 587
        #Sends secure emails
        #Deprecated but still somehow exists
        "LDAP (SSL/TLS)",
        #Lightweight Directory Access Protocol, 636
        #LDAP with a security blanket
        "FTPS",
        #File Transfer Protocol Secure, 989-990
        #FTP, glowed up
        "MSSQL",
        #Microsoft SQL Server, 1433
        #Everyone needs a friend, this port talks to Microsoft SQL Servers so it doesn't get lonely
        "Oracle Database",
        #1521
        #The oracle of databases
        "PPTP",
        #Point-to-Point Tunneling Protocol, 1723
        #Creates a VPN
        "MySQL",
        #3306
        #MySQL databases chatting like one big nerdy group chat
        "RDP",
        #Remote Desktop Protocol, 3389
        #VIP pass to remote desktops
        "VNC",
        #Virtual Network Computing, 5900
        #Remote desktop for the people

    ],
    "Cryptography and Encryption": [
        "Symmetric Cryptography",
        #One key, two key, same key to rule them all! 
        #Encryption/Decryption twins
        #Pros it's speedy, but key distribution and scalability aren't as cool here
        #Algorithms: AES, DES, Blowfish
        "Asymmetric Cryptography",
        #Two keys, one heart
        #Encryption: You grab the recipient’s public key, then lock it up so tight only their private key can open it.
        #Digital signatures: Use your private key to slap on a "this is definitely me" sticker, and everyone with your public key gets to verify you’re not full of it.
        #Safe sharing, but slow as dial-up in the 90s
        #Algorithms: RSA, ECC
        "RC Family Encryption",
        #The RC Clan
        #Algorithms built for speed and efficiency
        "RSA",
        #The big-shot asymmetric algorithm, RSA is everywhere
        #Built on prime numbers so big, even your calculator's scared
        #SSl/TLS, digital certs, signing things people knows it's legit
        "Diffie-Hellman",
        "Message Digest Functions",
        #Hash is out
        #Produces a little 'hash' of your data so you can say 'Ya nothin changed'. Like a digital fingerprint
        #One way trip baby, no going back to the original data
        #MD5, MD6-not the cool kids, SHA super cool
        "MD5",
        #The Fragile One, vulnerable to collisions (two different things could get the same hash, which is a big no-no)
        "MD6",
        #Tried to be the MDs family's comeback kid by fixing MD5's flaws
        #Flexible output lengths, but wasn't crowned king
        "SHA",
        #Family of hash functions designed to keep things airtight in integrity checks
        #SHA-1? Outdated. SHA-2 and SHA-3? Still strutting around, make sure it's 256 at least
        "Public Key Infrastructure",
        #The Certificate Mafia
        #The Certificate Authority(the boss) issues certificates, a Registration Authority(the bouncer) for verification, and a repository(the safe) for storage
        #Essential in SSL/TLS, secure email, and VPNs for identify verification and data encryption-anywhere trust is a must
        "Signed Certificate",
        #A certificate that says, "I'm official", issued by a trusted Certificate Authority, provides assurance of authority
        #Holds public key and identity details with the CA’s digital seal of approval
        #SSL/TLS
        "Self Signed Certificate",
        #DIY Security, homemade certificate
        #Created and signed by the entity using it
        #Free and fast, but like having your mom as a reference on your resume. 
        "Digital Signature",
        #Cyber John Hancock
        #Confirms you're the real deal and haven't been tampered with
        #Signed with your private key, verified with your public key
        #Emails, software, contracts—anywhere you don’t want fraudsters playing pretend.
        "SSL",
        #Protocol for encrypting internet traffic, providing security for data transmitted over the network
        #Used to be the internet’s bodyguard, encrypting data between users and websites.
        #Replaced by TLS because SSLv2 and SSLv3 were weaklings in the cryptographic gym.
        "TLS",
        #SSL's beefed up successor
        #Symmetric and asymmetric encryption plus certificates. Triple whammy of security.
        "Pretty Good Privacy",
        #the Swiss Army knife of encryption 
        #Uses symmetric encryption (for data) and asymmetric encryption (for key exchange) plus hashing, a little of everything
        #If you're paranoid about emails and files like embarassing selfies, PGP is your bestie
        "Web of Trust"
        #AKA Trust the friend of your friend's friend
        #Alternative to PKI that uses decentralized trust model for verifying authorities, because who needs real authority?
        #It's like a cryptographic commune. Users vouch for each other's keys, building a circle of trust like a digital secret society
        "Twofish Encryption",
        #Not the top of the food chain, but still has plenty of street cred
        #Symmetric block ciper, but not as popular as AES
        #Uses a 128-bit block size and key size up to 256 bits
        #Super secure, and flexible, works on everything from your phone to a potato powered computer (probably?)
        "Trust Platform Module", 
        #The brainy bounce of cryptograpy baby!
        #It's a hardware chip that hoards encryptions keys and passwords. Like a Fort Knox cookie jar, except the cookies are your juicy secrets
    ],
    "Windows_auth_protocols":[
        "SAM Database",
        #Like a password vault sans sexy user interface, it stores hashed passwords for local accounts tucked away like your deepest darkest secrets
        #Hiding out at C:\Windows\System32\config\SAM
        #SYSKEY adds an ecryption layer, which sounds great until hackers boot from another OS 
        #Common exploit techniques include LSASS memory dumping, Pass-the-Hash, and other hacker party tricks
        #Pro Tip for Bad Guys™: Tools like Mimikatz or LSASS memory dumping make SAM databases spill their guts
        "NTLM (NT LAN Manager) Authentication",
        #Windows login bouncer from the '90s
        #Challenge response authentication protocol
        #Uses hashed credentials, client sends the hash of the password
        #Vulnerable to Pass-the-Hash (PtH) and relay attacks, and lacks modern encryption and mutual authentication
        #Switch to Kerberos! Turn on SMB signing to make relays harder!
        "Kerberos Authentication",
        #The one with the tickets, Kerberos is the new hotness
        #Uses tickets to allow access to network services. It's like a Disneyland fast pass, no waiting in line (if you're legit)
        #Mutual authentication is kinda its thing
        #It uses symmetric key cryptography and a trusted third-party Key Distribution Center (KDC) that acts like Willy Wonka, handing out Golden Tickets (TGT)
        #Encrypted, mutual authentication, and makes NTLM look like a loser
        #Watch out for Kerberooasting, where hackers request service tickets for accounts with weak passwords
    ],
     "Malware":[
        "VAWTRAK Attack",
        #Financial Data's Worst Nightmare
        #Sophisticated banking trojan designed to sdteal fincial data, like credentials and credit card info
        #Malware that intercepts browsers sessions and disables antivirus, all to get into your sweet, sweet bank account
        "Logic Bomb",
    ],
    "Web Attacks":[
        "Clickjacking Attack",
        #Hackers trick you into clicking on hidden elements on a webpage by overlaying them on top of legit ones
        #It turns your innocent click into a nightmare. You think you're clicking on a cute cat meme, but it's really malware
        #All of a sudden your webcam is on, money is getting transferred, and you're left saying "I just wanted to see the cute cat meme!"
        #Countermeasures: HTTP headers like X-Frame-Options, Content Security Policy, and frame-busting scripts and Content Security Policy to control what can be loaded in a frame
        "Watering Hole Attack",
        #Hackers compromise a site everyone loves and infects you when you visit it. Why? Because they know you can't resist visiting it, classic toxic relatsh vibes
        #It delivers malware, data theft, and a sinking feeling everytime you see your favorite site
        #Monitor popular sites and slap on some endpoint protection
    ],
    "Network Attacks":[
        "DHCP Starvation",
        #Network attack that exhausts all available IP addresses of a DHCP server, preventing it from assigning new ones.
        #Like a pizza party where a jerk shows up and steals all the slices so no one else can have any.
        #The attacker spams your DHCP server with fake requests with spoofed MAC addys
        #The DHCP server, bless its trusting little heart, hands out all its IPs, leaving nothing for the good kids.
        #If you're the bad guy (which you aren't, right?), you'd use Yersinia or DHCPig. Great names, terrible intentions.
        #Countermeasures: 
        #Slap port security on your switches like its duct tape to a leaky pipe to limit the number of MAC addresses per port.
        #Use DHCP snooping to filter out the baddies in DHCP traffic.
        #Segregate DHCP traffic using VLANs so the chaos is contained.
        "STP Attack",
        #Spanning Tree Protocol Attack, the 'I'm the captain now of your network' move
        #STP keeps your network from tying itself in knots. An STP attack is where a hacker jumps in and says I'm in charge now by disrupting the topology of a network
        #The attacker sends out BPDUs (Bridge Protocol Data Units) claming to be the root bridge or the central switch in STP topology (aka STP royalty)
        #If it is successful, everyone believes them because switches are gullible
        #Traffic then starts to go through the attacker's device. Cue MITM attacks, sniffing, DoS, you know, all the bad stuff.
        "Wardrive Attack",
        #Drive-by hacking, just you and your buds cruising for unsecured networks
        #Use WPA3 encryption, and  hide SSIds
        "VLAN Hopping",
        #Network Ninja, Sneak Attack
        #Hackers bypass network segmentation and pop into other VLANS like an uninvited party guest
        #It exploits VLAN tagging protocols
        #Techniques? Switch spoofing and double tagging
        #Switch Spoofing: Pretend to be a trunking switch
        #Double tagging: Tricks switches into sending packets where they dont belong (unauthorized VLANs) by adding two VLAN tags to the packets.
        "DNS Cache Poisoning", #AKA DNS Spoofing
        #Hackers inject bogus entries into DNS servers, redirecting users to evil sites
        #Instead of Google, you get EvilHackerDaddy.com
        #Use DNSSEC and keep your server software updated, unless you like living dangerously and getting phished\
        "Domain Hijacking",
        #Hackers got control of your domain by compromising your domain registrar account and changing ownership details
        #Controls email, web traffic, DNS settings
        "DNS Flood",
        #Type of DDOS
        #Botnets flood DNS queries, servers taps out
        "DRDOS",#Distributed Reflection Denial of Service
        #Exploits DNS resolvers
        #Attacker sends spoofed (victim's ip) requests to open DNS resolvers
        #Resolvers respond to the victim with DNS reponses, flooding them with traffic
        #DNS server becomes the accomplice in an internet slap fight
        "DNS Tunneling",
        #Sneaky, sneaky, hacker smuggling data through DNS
        #Uses DNS as a covert channet to transmit data
        #Often for exfiltration, but can also be used for C&C
        "DNS hijacking",
        #Redirects traffic
        #Unlike spoofing, hijacking changes settings on the DNS server itself
        #So instead of going to legitgoodguys.com you end up at evilbadboys.com
        "NXDOMAIN Attack", #404 on Steroids
        #A DoS attack where hackers target DNS resolvers by flooding them for non-existent domains
        #The resolver is like '404 bro, I can't find that' until it crashes
        "Random Subdomain Attack", 
        #A DoS, it queries for random subdomains of a domain to overwhelm the authoritative DNS 
        "Phantom Domain Attack",#Ghost of Domains Past
        #Hacker setup fake domains that never respond or respond super super slow
        #Your DNS server waits like a fool for a response that never comes, just draining resources
        "Wireless Jamming",

    ],
    "Mobile Attacks":[
        "aLTEr Attack",
        #LTE, but make it evil
        #LTE (long-term evolution, the thing that keeps your phone from being useless) isn't perfect
        #This attack pokes holes in its user-plane encryption, letting hackers play peekaboo with your data
        #Targets mobile networks because hackers can't resist a juicy LTE connection
        #Result? Phishing, stolen creds, surveillance--basically a hacker's wet dream
    ],
     "Bluetooth Attacks":[
        "Bluesnarfing",
        #Hackers use your Bluetooth connection to steal your data without authorization, its a Bluetooth pickpocket
        #Goodbye contacts, email, and shameless selfies, hello identity theft
        "Bluebugging",
        #When hackers play puppetmaster
        #Hackers hijack your bluetooth device to make calls, send messages, and generally live your digital life without you
        #Can result in data theft, surveillance, and general chaos
        "Bluejacking",
        #Hackers send unsolicited messages or files to nearby Bluetooth devices, spamming people never goes out of style!
        #Annoying but harmless, unless you fall for phishing, in which case, you're in trouble
        #Set Bluetooth to non-discoverable mode 
        "Bluesmacking",
        #Bluetooth DoS. Device flooded with bad packets unitl it crashes. 
        #It's a temporary crash but enough to ruin your Bluetooth groove
    ],
    "Password Attacks":[
        "Non-Electronic Password Attacks",
        #Physical or social engineering techniques, shoulder surfin like a professional creep, or dumpster divin like a raccoon with a hacking fetish
        "Active Online Attacks",
        #Direct interaction, no consent!
        #Try every word in Webster's dictionary or smash every key until it works
        #Brute force, dictionary attacks, and credentials stuffing
        "Passive Online Attacks",
        #No active interaction, more like eavesdropping with you're best bud Wireshark
        #If the password is in plaintext, congrats it's mine now
        "Offline Attacks",
        #Grab the password hash database, then crack it offline
        #Think rainbow tables, dictionary attacks or brute force on steriods
        "Password Salting",
        #Add random junk to passwords before hashing
        #If two users pick 'password123' (ugh) their hashes will be different
        #Salt values are stored with the hash, and both are required for verification
    ],
    "Buffer Overflow":[
        "Buffer Overflow",
        #Occurs when a program gets more data than it can handle, and starts scribbling over adjacent memory space like a toddler with crayons
        #Can lead to crashes, arbitrary code execution, or privilege escalation
        "Stack-based Buffer Overflow",
        #Happens in the stack (fixed memory region for function calls and local variables) 
        #Attackers overwrite the return address stored on the stack to make the program do their bidding
        #Tools like Metasploit turn this into a hacking buffet 
        "Heap-based Buffer Overflow",
        #Occurs in the heap (dynamically allocated memory region) 
        #Hackers mess with memory structures to redirect the program's flow. Complex, yes, but also effective
        "Return-Oriented Programming (ROP) Attacks",
        #One kind of fancy schmany payload hackers deliver through buffer overflows, like hiding a rattlesnake in a bouqet of roses
        #Advanced buffer overflow technique that reuses existing code (gadgets) already in the program's memory, AKA hiding something dangerous inside something seemingly harmless
    ],
    "Cloud Computing":[
        "Cloud Computing",
        #Where your data floats in fancy servers
        #It's a computing paradigm where resources like servers, storage, apps, are delivered on a pay-as-you-go basis
        "Public cloud",
        #Cloud couch surfing
        #Think Google Cloud, AWS, Azure
        #Resources here are shared, you get the benefits of cloud computing without the commitment
        #Cheap and scalable, but security/privacy? Meh, not great
        "Private cloud",
        #The luxury penthouse in the clouds
        #All resources are dedicated to a single organization, making it a control freak's wet dream
        #Super secure, but also super expensive
        "Hybrid cloud",
        #Mullet cloud, business up front, party in the back
        #Part public, part private, all benefits
        #Allows data and apps to be shared between clouds, giving you the best of both worlds
        #Perfect if you want locked down security with scalable swagger
        #This is needing to keep your secrets under wraps while also flexing on a budget
        "Community cloud",
        #Cloud for the people, by the people
        #The neighborhood potluck
        #Shared by organizations with similar needs, like government, healthcare, or finance
        #Promotes collaboration and compliance. Team work makes the dream work, but compliance keeps the dream legal!

    ],
    "Cyber Threat Tactics":[
        "Domain Generation Algorithm (DGA)",
        #A technique used by malware to create a gazillion domain names for its C&C servers, making them harder to block
        #Malware stays connected no matter how many domains you take down
        #Peep threat intelligence feeds to keep up and use DNS filtering to stay ahead
    ],
}

def study_quiz():
    score = 0 
    total_concepts = 0 
    known_concepts = []
    skipped_concepts = []
    
    print("Welcome to the CEH Concept Quiz, aka 'Who Needs Social Life When You Have CEH?'")
    print("Type 'knew it' if you recall the concept, 'skip' if you're too cool for it, or 'exit' to call it quits.")

    while True:
        topic = random.choice(list(concepts.keys()))
        concept = random.choice(concepts[topic])
        
        print(f"\n--- CEH Study Concept ---\nTopic: {topic}\nConcept: {concept}")
        user_input = input("\nType '1 for knew it' if you recall this concept, '2 for skip' to move on, or ' 69 exit' to finish: ").strip().lower()
        
        if user_input == '1':
            score += 1
            total_concepts += 1
            known_concepts.append((topic, concept))
            skipped_concepts.append((topic, concept)) 
            print(random.choice([
                "Bam! You're killing it! Like, actually killing it.",
                "Correct! And you didn't even have to break a sweat.",
                "Impressive... I might even say 'heroic'... but let's not get carried away.",
                "Boom! Look at that big brain!"
            ]))
        elif user_input == '2':
            total_concepts += 1
            print(random.choice([
                "Skipping, huh? Running away..tsk,tsk.",
                "Moving on! Can’t say I’m surprised.",
                "Ah, skipping... Just like me avoiding all forms of adult responsibility.",
                "Next! You’ll totally get the next one... maybe."
            ]))
        elif user_input == '69':
            print("Done already? Alright, let’s tally up your score...")
            break
        else:
            print("That's not an option. But nice try, you little hacker in training.")

    print(f"\nQuiz complete! You recalled {score} out of {total_concepts} concepts correctly.")
    if score == total_concepts:
        print("Legendary! You’ve got the skills and, shockingly, the responsibility to match.")
    elif score > total_concepts // 2:
        print("Solid effort! You're on track to be... mildly impressive. Keep going!")
    else:
        print("Keep studying, my friend. Because at this rate, you’re more likely to be the sidekick than the superhero.")
    print("\n--- Detailed Summary ---")
    print("\nConcepts You Knew:")
    for topic, concept in known_concepts:
        print(f"- Topic: {topic} | Concept: {concept}")
    print("\nConcepts You Skipped:")
    for topic, concept in skipped_concepts:
        print(f"- Topic: {topic} | Concept: {concept}")

# Run the quiz
study_quiz()
