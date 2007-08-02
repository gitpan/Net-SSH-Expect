package Net::SSH::Expect;
use 5.008000;
use warnings;
use strict;
use fields qw(
	host user password port no_ptty escape_char ssh_option
	raw_pty exp_internal exp_debug log_file log_stdout
	timeout terminator ssh_connection debug next_line
);
use Expect;
use Carp;
use POSIX qw(:signal_h WNOHANG);

our $VERSION = '1.00';

# error contants
use constant ILLEGAL_STATE => "IllegalState";
use constant ILLEGAL_STATE_NO_SSH_CONNECTION => "IllegalState: you don't have a valid SSH connection to the server";
use constant ILLEGAL_ARGUMENT => "IllegalArgument";
use constant SSH_AUTHENTICATION_ERROR => "SSHAuthenticationError";
use constant SSH_PROCESS_ERROR => "SSHProcessError";
use constant SSH_CONNECTION_ERROR => "SSHConnectionError";
use constant SSH_CONNECTION_ABORTED => "SSHConnectionAborted";

$SIG{CHLD} = \&reapChild;

sub new {
    my $type = shift;
	my %args = @_;
    my Net::SSH::Expect $self = fields::new(ref $type || $type);
	
	# Options used to configure the SSH command
    $self->{host} 			= $args{host}|| undef; 
    $self->{user}  			= $args{user} || $ENV{'USER'}; 
    $self->{password} 		= $args{password} || undef;
	$self->{port}			= $args{port} || undef;			# ssh -p
	$self->{no_ptty}		= $args{no_ptty} || 0; 			# ssh -T
	$self->{escape_char}	= $args{escape_char} || undef; 	# ssh -e
	$self->{ssh_option}		= $args{ssh_option} || undef;	# arbitrary ssh options
	
	# Options used to configure the Expect object
	$self->{raw_pty}		= $args{raw_pty} || 0;
	$self->{exp_internal}	= $args{exp_internal} || 0;
	$self->{exp_debug}		= $args{exp_debug} || 0;
	$self->{log_file} 		= $args{log_file} || undef;
	$self->{log_stdout}		= $args{log_stdout} || 0;
	
	# Attributes for this module 
	$self->timeout(defined $args{timeout} ? $args{timeout} : 1);
	$self->{terminator} 	= $args{terminator} || "\n";
	$self->{next_line}		= "";
	$self->{ssh_connection} = undef;
	$self->{debug}			= $args{debug} || 0;

	# validating the user input
	foreach my $key (keys %args) {
		if (! exists $self->{$key} ) {
			croak ILLEGAL_ARGUMENT . " attribute '$key' is not a valid constructor argument.";
		}
	}

	return $self;
}

sub _connection_aborted {
	croak (SSH_CONNECTION_ABORTED);
}

# string login ([$test_success]) - authenticates on the ssh server. This should die if login fails.
# param:
#	boolean $test_success: 0 | 1. if 1, login will do an extra-text to verify if the password
# 		entered was accepted. The test consists in verifying if, after sending the password,
#		the "Password" prompt shows up again. This indicates the password was rejected.
#		This test is disabled by default.
# returns:
#	string: whatever the SSH server wrote in my input stream after loging in. This usually is some
#		welcome message and/or the remote prompt. You could use this string to do your verification
#		that the login was successful. The content returned is removed from the input stream.
# dies:
#	IllegalState: if any of 'host' or 'user' or 'password' fields are unset.
#	SSHProccessError: if can't spawn the ssh process
# 	SSHConnectionError: if the connection failed for some reason, like invalid 'host' address or network problems.
sub login {
    my Net::SSH::Expect $self = shift;
	my $test_success = @_ ? shift : 0;

	my $user = $self->{user};
	my $host = $self->{host};
	my $password = $self->{password};
	my $timeout = $self->{timeout};
	my $port = $self->{port};
	my $t = $self->{terminator};
	my $log_file = $self->{log_file};
	my $log_stdout = $self->{log_stdout};
	my $exp_internal = $self->{exp_internal};
	my $exp_debug = $self->{exp_debug};
	my $no_ptty = $self->{no_ptty};
	my $raw_pty = $self->{raw_pty};
	my $escape_char = $self->{escape_char};
	my $ssh_option = $self->{ssh_option};
	
	croak(ILLEGAL_STATE . " field 'user' is not set.") unless $user;
	croak(ILLEGAL_STATE . " field 'password' is not set.") unless $password;
	croak(ILLEGAL_STATE . " field 'host' is not set.") unless $host;
	
	# Gather flags.
	my $flags = "";
	$flags .= $escape_char ? "-e '$escape_char' " : "-e none ";
	$flags .= "-p $port " if $port;
	$flags .= "-T " if $no_ptty;
	$flags .= $ssh_option if $ssh_option;
	
	my $ssh_string = "ssh $flags $user\@$host";
	my $ssh = new Expect();
	
	$ssh->log_stdout($log_stdout);
	$ssh->log_file($log_file, "w") if $log_file;
	$ssh->exp_internal($exp_internal);
	$ssh->debug($exp_debug);
	$ssh->raw_pty($raw_pty);	
	$ssh->restart_timeout_upon_receive(1);
	$ssh->spawn($ssh_string) or croak SSH_PROCESS_ERROR . " Couldn't start ssh: $!\n";
	
	# saving this connection
	$self->{ssh_connection} = $ssh; 
	
	# loggin in
	$ssh->expect($timeout,
		[ qr/\(yes\/no\)\?\s*$/ => sub { $ssh->send("yes$t"); exp_continue; } ],
		[ qr/[Pp]assword.*?:|[Pp]assphrase.*?:/  => sub { $ssh->send("$password$t"); } ],
		[ qr/$password$/		=> sub { $self->_retry ($password); return exp_continue; } ],
		[ qr/ogin:\s*$/         => sub { $ssh->send("$user$t"); exp_continue; } ],
		[ qr/$user$/			=> sub { $self->_retry ($user); return exp_continue; } ],
		[ qr/REMOTE HOST IDEN/  => sub { print "FIX: .ssh/known_hosts\n"; exp_continue; } ],
		[ qr/yes$/				=> sub { $self->_retry("yes"); exp_continue; }], 
		[ timeout				=> sub 
			{ 
				croak SSH_AUTHENTICATION_ERROR . " Login timed out. " .
				"The input stream currently has the contents bellow: " .
				$self->peek();
			} 
		],
		[ eof					=> \&_connection_aborted ]
	);
	
	# verifying if we failed to logon
	if ($test_success) {
		$ssh->expect($timeout, 
			[ qr/[Pp]assword.*?:|[Pp]assphrase.*?:/  => 			
				sub { 
					my $error = $ssh->before() || $ssh->match();
					croak(SSH_AUTHENTICATION_ERROR . " Error: Bad password [$error]");
				}
			]
		);
	}

   	# swallows any output the put in my input stream after loging in	
	my $welcome_msg;
	while ($ssh->expect($timeout, '-re', qr/[\s\S]+/)) {
		$welcome_msg .= $ssh->match();
	}

	return $welcome_msg;
}


# ($prematch, $match) = waitfor ($pattern [, $timeout])
# This method reads until a pattern match or string is found in the input stream.
# All the characters before and including the match are removed from the input stream.
#
# In a list context the characters before the match and the matched characters are returned 
# in $prematch and $match. In a scalar context, the matched characters and all characters
# before it are discarded and 1 is returned on success. On time-out, eof, or other failures,
# for both list and scalar context, the error mode action is performed. See errmode().
#
#
sub waitfor {
	my Net::SSH::Expect $self = shift;
	my $pattern = shift;
	my $timeout = @_ ? shift : $self->{timeout};
	my $ssh = $self->get_expect();

	my $match = "";
	my $pre_match = "";
	$ssh->expect($timeout, 
		[qr/$pattern/ => 
			sub {
				$match = $ssh->match();
				$pre_match = $ssh->before();
			}
		],
		[ eof => \&_connection_aborted ]
	);
	
	my $list_context = wantarray() ? 1 : 0;

	if ($list_context) {
		return ($pre_match, $match);
	} else {
		if ($match) {
			return 1;
		} else {
			return 0;
		}
	}
}

# send ("string") - breaks on through to the other side.
sub send {
	my Net::SSH::Expect $self = shift;
	my $send = shift;
	croak (ILLEGAL_ARGUMENT . " missing argument 'string'.") unless ($send);
	my $ssh = $self->get_expect();
	my $t = $self->{terminator};
	$ssh->send($send . $t);
}

# peek([$timeout]) - returns what is in the input stream without removing anything
sub peek {
	my Net::SSH::Expect $self = shift;
	my $timeout = @_ ? shift : $self->{timeout};
	my $ssh = $self->get_expect();
	
	unless (defined $ssh->before() && $ssh->before() ne "") {
		my ($pos, $error, $match, $before, $after) = $ssh->expect($timeout);
		unless (defined $before && !($before eq "")) {
			# validates that the SSH connection was not terminated yet
			my $error_first_digit = substr($error, 0, 1);
			if ($error_first_digit eq '2') {
				croak (ILLEGAL_STATE_NO_SSH_CONNECTION);
			} elsif ($error_first_digit eq '3') {
				croak (SSH_PROCESS_ERROR . " The ssh process was terminated.");
			}
		}
	}
	return $ssh->before();
}

# string eat($string)- removes all the head of the input stream until $string inclusive.
#	eat() will only be able	to remove the $string if it's currently present on the 
#	input stream because eat() will wait 0 seconds before removing it.
#
#	Use it associated with peek to eat everything that appears on the input stream:
#
#	while ($chunk = $ssh->eat($ssh->peak())) {
#		print $chunk;
#	}
#	
#	Or use the readAll() method that does the above loop for you returning the accumulated
#	result.
#
# param:
#	string: a string currently available on the input stream. 
#		If $string doesn't start in the head, all the content before $string will also
#		be removed. 
#
#		If $string is undef or empty string it will be returned immediately as it.
#	
# returns:
#	string: the removed content or empty string if there is nothing in the input stream.
# 
# debbuging features:
#	The following warnings are printed to STDERR if $ssh->debug() == 1:
#		eat() prints a warning is $string wasn't found in the head of the input stream.
#		eat() prints a warning is $string was empty or undefined.
#
sub eat {
	my Net::SSH::Expect $self = shift;
	my $string = shift;
	unless (defined $string && $string ne "") {
		if ($self->{debug}) {
			carp ("eat(): param \$string is undef or empty string\n");
		}
		return $string;
	}

	my $ssh = $self->get_expect();

	# the top of the input stream that will be removed from there and
	# returned to the user
	my $top;

	# eat $string from (hopefully) the head of the input stream
	$ssh->expect(0, '-ex', $string);
	$top .= $ssh->match();

	# if before() returns any content, the $string passed is not in the beginning of the 
	# input stream.
	if (defined $ssh->before() && !($ssh->before() eq "") ) {
		if ($self->{debug}) {
			carp ("eat(): param \$string '$string' was found on the input stream ".
				"after '". $ssh->before() . "'.");
		}
		$top = $ssh->before() . $top; 
	}
	return $top;
}

# string readAll([$timeout]) - reads and remove all the output from the input stream.
# The reading/removing process will be interrupted after $timeout seconds of inactivity
# on the input stream.
sub readAll {
	my Net::SSH::Expect $self = shift;
	my $timeout = @_ ? shift : $self->{timeout};
	my $ssh = $self->get_expect();
	my $out;
	my $chunk;
	while ($chunk = $self->eat($self->peek($timeout))) {
		$out .= $chunk;
	}
	return $out;
}


# boolean hasLine([$timeout]) - tells if there is one more line on the input stream
sub hasLine {
	my Net::SSH::Expect $self = shift;
	my $timeout = @_ ? shift : $self->{timeout};
	$self->{next_line} = $self->readLine($timeout);
	return !($self->{next_line} eq "");
}

# string readLine([$timeout]) - reads the next line from the input stream
sub readLine {
	my Net::SSH::Expect $self = shift;
	my $timeout = @_ ? shift : $self->{timeout};
	my $line = $self->{next_line};
	if ($line eq "") { 
		my $nl;
		($line, $nl) = $self->waitfor('\n', $timeout);
	} else {
		$self->{next_line} = "";
	}
	return $line;
}

# string exec($cmd [,$timeout]) - executes a command, returns the complete output
sub exec {
	my Net::SSH::Expect $self = shift;
	my $cmd = shift;
	my $timeout = @_ ? shift : $self->{timeout};
	$self->send($cmd);
	return $self->readAll($timeout);
}

sub close {
	my Net::SSH::Expect $self = shift;
	my $ssh = $self->get_expect();
	$ssh->hard_close();
	return 1;
}

# returns 
#	reference: the internal Expect object used to manage the ssh connection.
sub get_expect {
	my Net::SSH::Expect $self = shift;
	my $exp = defined ($self->{ssh_connection}) ? $self->{ssh_connection} : 
		croak (ILLEGAL_STATE_NO_SSH_CONNECTION);
	return $exp;
}

sub reapChild {
   do {} while waitpid(-1,WNOHANG) > 0;
}

#
# Getter/Setter methods
#

sub host {
	my Net::SSH::Expect $self = shift;
	croak(ILLEGAL_ARGUMENT . " No host supplied to 'host()' method") unless @_;
	$self->{host} = shift;
}

sub user {
	my Net::SSH::Expect $self = shift;
	croak(ILLEGAL_ARGUMENT . " No user supplied to 'user()' method") unless @_;
	$self->{user} =shift;
} 

sub password{
	my Net::SSH::Expect $self = shift;
	croak(ILLEGAL_ARGUMENT . " No password supplied to 'password()' method") unless @_;
	$self->{password} = shift;
}

sub port {
	my Net::SSH::Expect $self = shift;
	croak(ILLEGAL_ARGUMENT . " No value passed to 'port()' method") unless @_;
	my $port = shift;
	croak (ILLEGAL_ARGUMENT . " Passed number '$port' is not a valid port number") 
		if ($port !~ /\A\d+\z/ || $port < 1 || $port > 65535);
	$self->{port} = $port;
}

# boolean debug([0|1]) - gets/sets the $ssh->{debug} attribute.
sub debug {
	my Net::SSH::Expect $self = shift;
	if (@_) {
		$self->{debug} = shift;
	}
	return $self->{debug};
}

# number timeout([$number]) - get/set the default timeout used for every method 
# that reads data from the input stream. 
# The only exception is eat() that has its timeout defined as 0.
sub timeout {
	my Net::SSH::Expect $self = shift;
	if (! @_ ) {
		return $self->{timeout};
	}
	my $timeout = shift;
	if ( $timeout !~ /\A\d+\z/ || $timeout < 0) {
		croak (ILLEGAL_ARGUMENT . " timeout '$timeout' is not a positive number.");
	}
	$self->{timeout} = $timeout;
}


1;


