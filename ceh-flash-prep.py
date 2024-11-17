import random

concepts = {
    "Cryptography": [
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
        #It's like a cryptographic commune. Users vouch for each other's keys, building a circle of trust like a digital secret societyrew 
    ],
    "Misc. Attacks":[
        "DHCP Starvation",
        "STP Attack",
        "aLTEr Attack"
    ],
    "Basics":[
        "Info Sec",
        "Elements of Info Sec",
        "5 Classifications of Attack",
        "Categories of Info War",
        "CEH Methodology",
        "Cyber Kill Chain Methodology Phases",
        "TTPs",
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
