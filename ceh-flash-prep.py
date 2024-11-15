import random

concepts = {
    "Cryptography": [
        "Symmetric Cryptography",
        "Asymmetric Cryptography",
        "RC Family Encryption",
        "RSA",
        "Diffie-Hellman",
        "Message Digest Functions",
        "MD5",
        "MD6",
        "SHA",
        "Public Key Infrastructure",
        "Signed Certificate",
        "Self Signed Certificate",
        "Digital Signature",
        "SSL",
        "TLS",
        "Pretty Good Privacy",
        "Web of Trust"
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
