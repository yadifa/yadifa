#!/bin/sh

KEYGEN=/usr/sbin/dnssec-keygen
DOMAIN=example.eu.
FLAG_FILE=generated.flag
if [ ! -f $FLAG_FILE ]
then
	rm -f K*.key K*.private

	for as in RSASHA1:4096 NSEC3RSASHA1:4096 RSASHA256:1024 RSASHA256:2048 RSASHA256:4096 RSASHA512:4096 ECDSAP256SHA256: ECDSAP384SHA384: ED25519: ED448:
	do
		a=$(echo $as|sed 's/:.*//')
		s=$(echo $as|sed 's/.*://')

		if [ ! "x$s" = "x" ]
		then
		    b="-b $s"
		fi

		$KEYGEN -a $a $b $DOMAIN
	done

	touch $FLAG_FILE
fi

for f in K*.key
do

b64key=$(grep DNSKEY $f|awk '{$1=$2=$3=$4=$5=$6=""; print $0}'|sed 's/ //g')
#echo "// b64='$b64key'"
bits=$(echo -n $b64key|base64 -d|wc -c)
echo "// bits='$bits'"
tag=$(echo $f|sed -e 's/.*+//' -e 's/\.key//' -e 's/^0*//g')
echo "// tag=$tag"
echo '{'
echo \"$(grep DNSKEY $f)\",
echo $(grep DNSKEY $f|awk '{print $6}'), $bits '* 8', $tag, \"$DOMAIN\",
echo \"$f\",
echo '},'

done

for f in K*.private
do

tag=$(echo $f|sed -e 's/.*+//' -e 's/\.private//' -e 's/^0*//g')
echo "// tag=$tag"
echo '{'
echo '   ' $tag,
echo \"$f\",
cat $f|sed -e 's/^/    "/g' -e 's/$/\\n"/g'
echo '},'

done

