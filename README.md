# Baseline Considerations and commonly accepted best practices for usage with Apple Mac's running macOS 10.14.x 

# Sec-Baseline.md  


# Baseline Security for Modern Apple Macs running macOS Mojave 10.14.x (darwin kernel 18.0)
This Program is intended AS IS.
baseline init for secure macOS systems (as of 10.14.x)
This program is merely an outline whose guidelines concern hardening, at an extremely simplistic & high-level darwin/macOS system (as ox kernel 18/Mojave base 14.x)
Therefore, it shall NOT, serve nor does it attempt to be, a complete substitute nor extremely secure tweaked system to be used in favor of macOS.
This program and its contents are merely intended as a 'baseline' secure generalized overview of systems tweaks centered around "power-users"(people who are the least bit concerned with their systems and what they type into it.)
To reiterate: DO NOT, type these command blindly without prior knowledge and full understanding of their outcome.
In no way, shape, form or factor am i responsible for whatever happens to anyone whom decides to proceed with the following commands.



echo " enabling SIP Master Assesments Enabled"
echo "code: sudo spctl --master-enable && sudo csrutil --enable"
sudo csrutil --status && sudo spctl --master-enable

echo "Security Assesments for thirdparty programs are now being enforced; please restart to recovery and proceed to enable SIP integrity in order to reinforce apple's hardware and software integrity compliance with given system's proper matching hash values (all subsequent hash values and file integratity sums are public knowledge and accesible either thru apple's own website or by means of a simple google search. )"
echo "Keep in mind, most significant hashes and values are issued by Apple's Root Certificate Authority (on a shameless SHA-1 Root Cert and subsequent leaf certificates with ciphers => sha-256|| 4096bits) "




function harden_sys_frontend {
	defaults read /System/Library/com.apple.alf.plist | grep --color=auto 'globalstate'

	echo "parse firewall basics"

	sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on &&\
	echo "block all $PATH included, internal applications by default. (require further user discrimination)"
	sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setloggingmode on &&\
	echo "enforce STEALTH MODE (do not respond to outgoing/ingoing PING commands sent by local/external computers/botnets/malware ...)"
	sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on &&\

	echo "disallow all applications from connecting to the internet without prior user consent."
	sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setallowsigned off &&\
	sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setallowsignedapp off &&\

	echo "launchdaemon and launchagents which were previously pertinent to macOS and are still supported by the system should be running by default, regardless of the kernel's implicit policy.
	Whence, their mere presence suggests not only their necessity but functionality (especillay concerning older protocols and intranetted machines running older smbd protocols, afp, appletalk
	or linux's nfs.)"

	echo "This Warning is of greater significance to systems administrators; whose authority extends to general worplace decisions:
	AFP, SMBv1,SMBv2 Have been depretecaed and shoudl be avoided at all costs !!!!! Strive towards a system whose overall intracommunications rely either heavily on NFS or SMBv3 w/ Enforced Encryption
	strict policy-based & user-based file access and permissions. (If at all possible, it is always a better idea to separate machines and networks upon their segments and capabilities. [i.e. Topological Decisions within the workplace that segregate LANS/VLANS and Networks into a permission based hierarchy .])"

	sudo launchctl load /System/Library/LaunchDaemons/com.apple.alf.agent.plist
	sudo launchctl load /System/Library/LaunchAgents/com.apple.alf.userargent.

	sudo pkill -HUP socketfilterfw
}

echo "PHASE 1 Complete :: Firewall Applied"

defaults read /Library/Preferences/com.apple.alf.plist | grep '{globalstate,stealthmode,loggingmode,}'

echo "default values should bem 2, 1, 1, respectively"


function harden_default_macOS_shell{
	# unhide user ~/Library
	echo "unhide `~/Library` Folder"
	chflags nohidden ~/Library

	defaults read NSGlobalDomain AppleShowAllFiles | grep -q '1'
	echo "default hiddenfiles remain hidden. unhide and fiddle with them at your own discretion(knowledge of such processes and files)"

	defaults write NSGlobalDomain AppleShowAllExtensions -bool true
	defaults write com.apple.Terminal SecureKeyboardEntry -bool true

	defaults write com.apple.desktopservices DSDontWriteUSBStores -bool true
	defaults write com.apple.desktopservices DSDontWriteNetworkStores -bool true
	echo "avoid writing Metadata to Networked Volumes and USB Stores/sticks/thumbs (.DS_Store files)"


	echo "basic default security settings for Apple's Safari and Mail"
	defaults write com.apple.Safari array-add {
			    AutoFillCreditCardData = 0;
			    AutoFillFromAddressBook = 0;
			    AutoFillMiscellaneousForms = 0;
			    AutoFillPasswords = 0;
			    AutoOpenSafeDownloads = 0;
			    DebugSnapshotsUpdatePolicy = 2;
			    IncludeInternalDebugMenu = 0;
			    InstallExtensionUpdatesAutomatically = 1;
			    SendDoNotTrackHTTPHeader = 1;
			    ShowFullURLInSmartSearchField = 1;
			    SuppressSearchSuggestions = 1;
			    UniversalSearchEnabled = 0;
			    WebAutomaticSpellingCorrectionEnabled = 0;
			    WebKitJavaEnabled = 0;
			    WebKitPluginsEnabled = 0;
			    WebsiteSpecificSearchEnabled = 0;
}
	echo "Developer Options Specific "
	defaults write com.apple.Safari "com.apple.Safari.ContentPageGroupIdentifier.WebKit2JavaEnabled" -bool false
    defaults write com.apple.Safari "com.apple.Safari.ContentPageGroupIdentifier.WebKit2PluginsEnabled" -bool false

function parse_basic_desktop_security_provisions{
	defaults write com.apple.screensaver askForPassword -int 1
	defaults write com.apple.screensaver askForPasswordDelay -int 0
}

echo "baisc power mgmt essentials to evade Cold Boot Attacks and EvilMaid exploits are not only for the paranoid but also for those whose concern extend throughout apple's extensive and apprently
pervasive usage of The iCloud Systems regardless of powerlevel,user consent, utilization or user knowledege(except for those whom read the fineprint :o|
echo "these security measures ensure, at base operating system level that your computer's data should remain within your contorl : Nevertheless,
the utilizing third party firewall systems are not only commomn and good practice but, to those serious about security: consider dedicating an entire separate machine towards controlling your systems's connections and possible outreach"
echo "for further information look into pfsense,opensese,ipfire or other WAF Based Programs (If you're compfortable enough handing out your data to another third party and their 'security solutions', please remember that opensource'd codebased systems are always
preferable (given their transparency by nature and their constant evolution.)"

**** echo "Recommended companies include but are not limited to: Photon, Cyclance, MalwareBytes,"

function pmset_related_options{
	sudo pmset -a hibernatemode 25
	sudo pmset -a destroyfvkeyonstandby 1
	sudo pmset -a standby 0
	sudo pmset -a standbydelay 0
	sudo pmset -a autopoweroffdelay 0
	sudo pmset -a powernap 0
	sudo pmset -a ring 0
	sudo pmset -a womp 0
	sudo pmset -a proximitywake 0
	sudo pmset -a ttyskeepawake 0
	sudo pmset -a tcpkeepalive 0
}

echo "These settings ensure, respectively: FileVault Encryption Keys will be removed from ram memory whenever the computer is asleep,
the computer will not enter idle standby regardless of sleeptimeout, no response or even a hint of availability should be elicited from commands such as
'Wake on Magic Packet' or 'Wake on Lan' >> The proverbial assumption here is these macs are being utilized as single machine and not server computer (thus they do not require default functionality for such commands ) "
echo "ProxmityWake: is a new feature enabled by apple eversince macOS 10.14.x (codename Mojave); has come frontward. It's primary concern is as follows:
if two apple devices, whom are logged into the same AppleID Account(the one you used to setup your computer/applestore)
	come into proximity to one another (less than an feet of distance) : (be'm either an applewatch&macbook || MBPro&Iphone) ;
these devices are understood to be part of the same apple habitat, as such, they're entitled to communicate with one another regardless of user interaction;
Consequently: they're also entitled to relay the information back to apple on a constant basis (as seen fit by the company :: >> to summon user data as per their own agenda.)."
}
echo " the subsequent options have been applied on a Personal-USER-Based preference system and should be taken into extreme caution when being utilized (especially by those whom have ignored my previous warnings...)"

# Concerning Apple's Captive Portal
sudo defaults write /Library/Preferences/SystemConfiguration/com.apple.captive.control -bool false

defaults write NSGlobalDomain AppleAntiAliasingThreshold -int 4
  │ defaults write NSGlobalDomain AppleFontSmoothing -int 2
 defaults write NSGlobalDomain AppleLocale -string "en_US"
 defaults write NSGlobalDomain AppleShowAllExtensions -bool true

 # UI/UX Preferences 
 defaults write NSGlobalDomain NSAutomaticCapitalizationEnabled -bool false
 defaults write NSGlobalDomain NSAutomaticDashSubstitutionEnabled -bool false
 defaults write NSGlobalDomain NSAutomaticPeriodSubstitutionEnabled -bool false
 defaults write NSGlobalDomain NSAutomaticQuoteSubstitutionEnabled -bool false
 defaults write NSGlobalDomain NSAutomaticSpellingCorrectionEnabled -bool false
 defaults write NSGlobalDomain NSAutomaticTextCompletionEnabled -bool false
 defaults write NSGlobalDomain NSDocumentSaveNewDocumentsToCloud -bool false
 defaults write NSGlobalDomain WebAutomaticSpellingCorrectionEnabled -bool false

 defaults write com.apple.finder _FXShowPosixPathInTitle -bool true
 defaults write com.apple.finder ShowPathBar -bool true
 defaults write com.apple.finder ShowStatusBar -bool true
 defaults write com.apple.finder
───────┴───────────────────────────────────────────────

# the overall project has been compiled from both experience and an incredible amount of numerous sources.
most notably it could not have been possible without the previous work done by 
dr.druh (macOS security basics) (pioneer of the initial 'macOS security "for the paranoids, explained for dummies by one seriously curious yet astute freaking freaking hacker/bsdnix guru'")
alichtman/stronghold (one of the first simple, concise and trustworthy "mac-sec"-centred automation frameworks for gh enthusiasts.)
mathiasbynens's notoriously and outstanding compendium of his own dotfiles (neverending working in progress) and a true mac/unix composition of useful dotfiles.
