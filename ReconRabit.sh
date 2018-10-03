#!bin/bash
#################################################################################################################
# @author Qu3b411												#
#################################################################################################################
#DOCUMENTATION													#
#################################################################################################################
# @param $1: the first three bytes of an ipv4 address								#
#		 I.E	X.X.X 											#
# @param $2: the output filename										#
#		 I.E 	'file.txt'										#
# description: analyzes 255 addresses with a quick scan, once all up hosts are determined and saves the 	#
# resulting output to an XML file.										#
#	filename nmap_#.#.#.XML											#
# does comprehensive in-depth scans of each and saves them to XML files according to their IP address		#
# 	example	nmap_#.#.#.#.XML										#
# organizes a comprehensive output for the user of the os statistics, then lists possible exploits from		#
# the exploitdb offline database.											#
#														#
# this script requires the installation of searchsploit, this can be acquired with apt-get exploitdb on a kali	#
# instalation, ensure that your searchsploit package is up to date when running this script			#
#														#
# this script further requires the installation of curl to query online files and obtain information		#
#################################################################################################################

cat RR_image
#nmap's the designated address space.
if [[ ( ! -z "$1" ) && ( ! -z "$2" )  ]]; then
	if [[  $1 =~ ^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])$ ]]; then
		
		echo -e "ReconRabbit is starting its investigation into the hosts on $1, please be patient ReconRabbit was drinking heavily!! \n\n"
		nmap --version-light -PS -f -O -F -T4 $1.0/24 -oX ./nmap_$1.XML >> /dev/null
	else
		if [[  $1 =~ [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3} ]]; then
			if [[ $1 =~ ^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])$ ]]; then
				echo "really, your going to scan only one IP, do it yourself you lazy bum!! if you want ReconRabbit help, just give ReconRabbit the first three octets, ReconRabbit will figure everything else out."
			else
				echo "oh, so close, you have 4 numbers separated by periods , but once again ReconRabbit is insulting your intelligence, go back to google and figure out how IPV4 works, good luck script kiddie, when you figure it out I may tell you the rest of your errors!"
			fi
		else
			echo "well well well, the ReconRabbit thinks you don't know anything about ipv4, go to google script kiddie"
		fi		
		exit
	fi
else
	echo -e "Sorry, ReconRabbit hit the bottle hard and can't investigate\n\n \t maybe if you give ReconRabbit the correct arguments he could drag his sorry ass out of bed \n\n";
	exit
fi 
# set the array of addrs based on the XML output of the light scan.
addrs=$(grep -E "\"ipv4\"+" ./nmap_$1.XML | xargs -n 1 | grep addr=.* | xargs -d "=" -n 1 |  grep -v addr)
# loop through the addrs array.
for line in $addrs;do 
	# do an intense scan of each up address 
	nmap --version-all -A T4 $line -oX ./nmap_$line.XML >> /dev/null
done
# print details of the host discovery nmap query to the designated file.
echo -e "host discovery command:\tnmap --version-light -PS -f -O -F -T4 $1.0/24 -oX ./nmap_$1.XML" > ./$2
# print the ip addresses of all discovered hosts to the designated file.
echo -e "\n\nHosts to be scanned:\n$addrs\n\n" >> ./$2
# iterate through each discovered address.
for line in $addrs;do
	# print the current host being discovered
	echo -e "BEGINNING HOST OUTPUT FOR $line\n" >>./$2
	# print details of the scan being conducted against the host
	echo -e "intense scan of host $line command:\tnmap --version-all -A -T4 $line -oX ./nmap_$line.XML\n\n">>./$2
	host=$(grep -Eo 'NetBIOS name:.*' nmap_$line.XML |xargs -n 3 -d ' '| grep 'NetBIOS name:.*' | xargs -n 2 | grep -v NetBIOS.* | grep -Eo "^[^,]+")
	# print the host name if discovered.
	echo -e "host name: $host\n" >>./$2
	# print the ip address that was discovered.
	echo -e "IP address: $line \n" >>./$2 
	echo "port and service info:">>./$2
	echo -e "port \t\t service /version">>./$2
	# loop through the XML file created in the intense scan and discover information about the open port service running and the version of the service.
	grep -Eo '<port .*' nmap_$line.XML| while read portinfostr; do
		port=$( echo $portinfostr |xargs -n 1 | grep -E 'portid=.*' | grep -Eo "^[^>]+" | xargs -n 1 -d "=" | grep -v "portid")
		product=$( echo $portinfostr |xargs -n 1 | grep -E 'product=.*' | grep -Eo "^[^>]+" | xargs -n 1 -d "=" | grep -v "product")
		version=$( echo $portinfostr |xargs -n 1 | grep -E 'version=.*' | grep -Eo "^[^>]+" | xargs -n 1 -d "=" | grep -v "version")
	echo -e "$port \t\t $product / $version\n">>./$2
	done # end the loop
	echo -e "potential host OS and SP details\n">>./$2
	# discover the potential operating systems running on the host device. 
	grep -Eo "<osmatch name.*" nmap_$line.XML | xargs -n 1 |grep name= | xargs -n 1 -d "=" | grep -v "name" >>./$2
	# discover exploits that may be used about the device. 
	echo -e "\n\npotential exploits\n" >>./$2
	# discover exploits and loop through them to gather desired information
	searchsploit -w --nmap nmap_$line.XML  | grep -Eo "https:.*" | sed 's/\x1b\[[0-9;]*m//g' | while read CVEdiscovery; do
		#discover the cve by posing a query to the exploit database website.
		CVE=$(curl $CVEdiscovery | grep "<meta name=\"description\".*" | xargs -d "." -n 1 | grep -Eo "CVE.*")
		#check to see if the CVE exists if their is no cve then skip.
		if [[ ! -z "$CVE" ]]; then 
			#print the cve and the URL in which the cve was discovered.
			echo -e "CVE: $CVE\nexploit-db source:$CVEdiscovery" >> $2
			# print the nist url where details of the CVE are listed.
			echo -e "Nist source: https://nvd.nist.gov/vuln/detail/$CVE" >> $2
			#pose a query to the Nist url and strip undesired information.
			description=$(curl https://nvd.nist.gov/vuln/detail/$CVE | grep -A 1 "\"vuln-description\"" | xargs -d ">" -n 1 | grep -v "<p" | rev | cut -c 4- | rev)
			# print to the file the description of the vulnerability. 
			echo -e "Description: \"$description \" \n\n" >>$2
		fi
	done # end the loop.
	# print a clear separator between hosts`
	echo -e "\n\n\n">>./$2
done # end the main loop.
