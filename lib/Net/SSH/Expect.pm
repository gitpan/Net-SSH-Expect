package Net::SSH::Expect;
########################################################
# Net::SSH::Expect.pm
# 	Wrapper for ssh remote exec funtion, with the ability to send passwords via Expect.
# AUTHOR: 
#	Bruno Negrao - brunonz@br.ibm.com
# NOTES:
#	This module is inspired in  http://search.cpan.org/~djberg/Net-SCP-Expect-0.12/Expect.pm
#	and some parts of the code was copied and pasted from the original. Thanks to Daniel Berger.
# CHANGES:
#	2007/06/08 - creation.
########################################################
use 5.008003;
use warnings;
use strict;
use fields qw(
	host user password verbose
	timeout error_handler
	cipher port terminator protocol identity_file
	log_file ssh_connection prompt
);
use Expect;
use Carp;
use POSIX qw(:signal_h WNOHANG);

our $VERSION = '0.02';

# error contants
use constant ILLEGAL_STATE => "IllegalState";
use constant ILLEGAL_STATE_NO_SSH_CONNECTION => "IllegalState: you don't have a valid SSH connection to the server";
use constant ILLEGAL_ARGUMENT => "IllegalArgument";
use constant SSH_AUTHENTICATION_ERROR => "SSHAuthenticationError";
use constant REMOTE_PROMPT_UNAVAILABLE => "RemotePromptUnavailable"; 
use constant SSH_PROCESS_ERROR => "SSHProcessError";
use constant SSH_CONNECTION_ERROR => "SSHConnectionError";
use constant SSH_CONNECTION_ABORTED => "SSHConnectionAborted";

$SIG{CHLD} = \&reapChild;

sub new {
    my $type = shift;
	my %args = @_;
    my Net::SSH::Expect $self = fields::new(ref $type || $type);
    $self->{host} 			= $args{host}|| undef;
    $self->{user}  			= $args{user} || $ENV{'USER'};
    $self->{password} 		= $args{password} || undef;
	$self->{auto_yes} 		= $args{auto_yes} || 1;
	$self->{verbose}		= $args{verbose} || 0;
	$self->{timeout}		= $args{timeout} || 10;
	$self->{error_handler} 	= $args{error_handler} || undef;
	$self->{cipher} 		= $args{cipher} || undef;
	$self->{port}			= $args{port} || undef;
	$self->{terminator} 	= $args{terminator} || "\r";
	$self->{identity_file}	= $args{identity_file} || undef;	 
	$self->{log_file} 		= $args{log_file} || undef;
	$self->{ssh_connection} = undef;
	$self->{prompt}			= 'SSH_PROMPT>> '; # will set the PS1 env variable to this when connected 
	return $self;
}



sub _connection_aborted {
	croak (SSH_CONNECTION_ABORTED);
}

# connect() - establishes an ssh connection with the ssh server
# dies:
#	IllegalState: if any of 'host' or 'user' or 'password' fields are unset.
#	RemotePromptUnavailable: if the prompt on the remote machine can't be obtained after establishing the ssh connection
#	SSHProccessError: if can't spawn the ssh process
# 	SSHConnectionError: if the connection failed for some reason, like invalid 'host' address or network problems.
sub connect {
    my Net::SSH::Expect $self = shift;
	
	my $user = $self->{user};
	my $host = $self->{host};
	my $password = $self->{password};
	my $auto_yes = $self->{auto_yes};
	my $timeout = $self->{timeout};
	my $handler = $self->{error_handler};
	my $cipher = $self->{cipher};
	my $port = $self->{port};
	my $terminator = $self->{terminator};
	my $identity_file = $self->{identity_file};
	my $verbose = $self->{verbose};
	my $protocol = $self->{protocol};
	my $log_file = $self->{log_file};
	my $prompt = $self->{prompt};
	
	croak(ILLEGAL_STATE . " field 'user' is not set.") unless $user;
	croak(ILLEGAL_STATE . " field 'password' is not set.") unless $password;
	croak(ILLEGAL_STATE . " field 'host' is not set.") unless $host;
	
	# Gather flags.
	my $flags = "";
	
	$flags .= "-c $cipher " if $cipher;
	$flags .= "-P $port " if $port;
	$flags .= "-v " if $verbose;
	$flags .= "-$protocol " if $protocol;
	$flags .= "-i $identity_file" if $identity_file;
	
	my $ssh_string = "ssh $flags $user\@$host";
	my $ssh = Expect->spawn($ssh_string) or croak SSH_PROCESS_ERROR . " Couldn't start ssh: $!\n";
	$ssh->log_stdout( $verbose ? 1 : 0  );
	$ssh->log_file($log_file, "w") if $log_file;
	
	# saving this connection
	$self->{ssh_connection} = $ssh; 
	
	$ssh->expect($timeout,
		[ qr/\(yes\/no\)\?\s*$/ => sub { $ssh->send("yes$terminator"); exp_continue; } ],
		[ qr/[Pp]assword.*?:|[Pp]assphrase.*?:/  => sub { $ssh->send("$password$terminator"); } ],
		[ qr/$password$/		=> sub { $self->_retry ($password); return exp_continue; } ],
		[ qr/ogin:\s*$/         => sub { $ssh->send("$user$terminator"); exp_continue; } ],
		[ qr/$user$/			=> sub { $self->_retry ($user); return exp_continue; } ],
		[ qr/REMOTE HOST IDEN/  => sub { print "FIX: .ssh/known_hosts\n"; exp_continue; } ],
		[ eof					=> \&_connection_aborted ]
	);
	 
	$ssh->expect($timeout, 
		[ qr/[Pp]assword.*?:|[Pp]assphrase.*?:/  => 			
			sub { 
				my $error = $ssh->before() || $ssh->match();
				if($handler){
					$handler->($error);
				} else{
					croak(SSH_AUTHENTICATION_ERROR . " Error: Bad password [$error]");
				}
			}
		]);
		
	# setting the prompt
	while ($ssh->expect($timeout, '-re', qr/.+/s)){
	}
	my $change_prompt_cmd = "PS1='$prompt'";
	$ssh->send("$change_prompt_cmd$terminator");
	$ssh->expect($timeout,
		[ qr/^$prompt$/ => 	sub { $ssh->send($terminator); } ],
		[ qr/^$change_prompt_cmd$/	=> sub { $self->_retry ($change_prompt_cmd); return exp_continue; }	],
		[ timeout => sub { croak (REMOTE_PROMPT_UNAVAILABLE . 
			": can't set the prompt with the command $change_prompt_cmd." ) ;} ],
		[ eof => \&_connection_aborted]
	);
}

# exec($cmd_string [, $block])  - executes a command in the remote machine
# params:
#	cmd_string: the string with the command to be ran.
#	block 0|1: 
#		0 - does not block untill prompt goes back, waiting utill 'timeout' seconds; 
#		1 - blocks waiting the prompt to return. 
#		This argument is optional and can be omitted. Default is 0.
# returns:
#	undef: if after running 'cmd_string' and waiting for 'timeout' seconds the prompt still didn't return. This can happen if 
#		'cmd_string' takes a long time to conclude.
#	empty string: if the command sent doesn't have output,
#	string: containing the output of the command ran. it can be a non readable character if this was the output.
# dies:
#	IllegalState: if this there is no valid ssh connection established
#	IllegalArgument: if no argument (no command string) is passed to this method.
#	RemotePromptUnavailable: if the prompt is not available for execution of 'cmd_string'
sub exec() {
    my Net::SSH::Expect $self = shift;
	my $cmd = shift;
	croak (ILLEGAL_ARGUMENT . " missing argument 'cmd_string'.") unless ($cmd);
	
	my $block = @_ ? shift : 0;
	
	my $ssh = $self->get_expect();
	my $timeout = $self->{timeout};
	my $terminator = $self->{terminator};
	my $user = $self->{user};
	my $prompt = $self->{prompt};

	# blocking is enabled by passing 'undef' as timeout to expect, causing it to block until the matching string comes available again
	$timeout = $block ? undef : $timeout;
	
	my $cmd_output = undef;
	$ssh->expect($timeout, 
		[qr/$prompt$/ 	=> 
			sub {
					$ssh->send($cmd . $terminator); 
					$ssh->expect($timeout, 
						[qr/$prompt$/ => 
							sub {
								$cmd_output = $ssh->before();	
								if (! defined $cmd_output || length($cmd_output) == 0 ) {
									$cmd_output = "";
								}
							}
						],
                        [timeout    =>
                            sub {
	                            if ($ssh->expect($timeout, '-re', qr/$cmd$/)) {
	                                 $self->_retry ($cmd); 
									 return exp_continue;
	                            } else { 
	                                croak (REMOTE_PROMPT_UNAVAILABLE .
	                                " exec(): can't get the remote prompt after running '$cmd'." );
	                            }
							}
                        ],
						[eof => \&_connection_aborted]
					);
			} 
		],
		[timeout 	=> 
			sub { 
				croak (REMOTE_PROMPT_UNAVAILABLE . 
				" exec(): can't execute command '$cmd' without the remote prompt available" );
			} 
		],
		[eof => \&_connection_aborted]
	);
	
	# sending a "\r" to make the prompt be available again (for the next call of exec())
	$ssh->send($terminator);
	
	return $cmd_output;
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
	my $ssh = defined ($self->{ssh_connection}) ? $self->{ssh_connection} : 
		croak (ILLEGAL_STATE_NO_SSH_CONNECTION);
	return $ssh;
}

# _retry ($string_to_resend);
sub _retry {
	my Net::SSH::Expect $self = shift;
	my $str = shift;
	my $ssh = $self->get_expect();
	my $terminator = $self->{terminator};
	$ssh->clear_accum();
	$ssh->send("$str$terminator");
}

# returns:
#	digit: the exist status of the last command ran with exec()
#	undef: if the last exist status could'n be obtained
sub last_exit_status {
	my Net::SSH::Expect $self = shift;
	my $stat = $self->exec("echo $?");
	chomp ($stat);
	return $stat;
}

sub host{
	my Net::SSH::Expect $self = shift;
	croak(ILLEGAL_ARGUMENT . " No host supplied to 'host()' method") unless @_;
	$self->{host} = shift;
}

sub user{
	my Net::SSH::Expect $self = shift;
	croak(ILLEGAL_ARGUMENT . " No user supplied to 'user()' method") unless @_;
	$self->{user} =shift;
} 

sub password{
	my Net::SSH::Expect $self = shift;
	croak(ILLEGAL_ARGUMENT . " No password supplied to 'password()' method") unless @_;
	$self->{password} = shift;
}

sub port{
	my Net::SSH::Expect $self = shift;
	croak(ILLEGAL_ARGUMENT . " No value passed to 'port()' method") unless @_;
	my $port = shift;
	croak (ILLEGAL_ARGUMENT . " Passed number '$port' is not a valid port number") 
		if ($port != /^[+-]?\d+$/ || $port < 1 || $port > 65535);
	$self->{port} = $port;
}

sub reapChild{
   do {} while waitpid(-1,WNOHANG) > 0;
}
1;

=head1 NAME

Net::SSH::Expect - SSH wrapper to execute remote commands

=head1 SYNOPSIS

	use Net::SSH::Expect;

	# configures the ssh connection and authentication
	my $ssh = Net::SSH::Expect->new (host => "myserver.com", password=> 'pass87word', user => 'bnegrao');

	# establishes the ssh connection, 
	# authenticating with that user and password
	$ssh->connect();

	# runs arbitrary commands
	my $ls = $ssh->exec("ls -l /");
	print($ls);

	my $who = $ssh->exec("who");
	print ($who);

	# closes the ssh connection
	$ssh->close();

=head1 DESCRIPTION

This module is a wrapper to the I<ssh> executable that is available in your system's I<$PATH>.
Use this module to execute commands on the remote SSH server.
It authenticates with the user and password you passed in the constructor's attributes
C<user> and C<password>.

Once an ssh connection was started using the C<connect()> method it will remain open
until you call the C<close()> method. This allows you execute how many commands you want
with the C<exec()> method using only one connection. This is a better approach over other 
ssh wrapper implementations, i.e: Net::SCP, Net::SSH and Net::SCP::Expect, that start a new
ssh connection each time a remote command is issued or a file is transfered.

It uses I<Expect.pm> module to interact with the SSH server. A C<get_expect()> method is 
provided so you can obtain the internal C<Expect> object connected to the SSH server. Use 
this only if you have some special need that you can't do with the C<exec()> method.

This module was inspired by Net::SCP::Expect L<http://search.cpan.org/~djberg/Net-SCP-Expect-0.12/Expect.pm>
was designed to be its counterpart. Their API's are very similar, and sometimes identical.
I'll refer to the documentation of Net::SCP::Expect anytime their functionality is the same.

=head2 EXPORT

None by default.

=head1 CONSTRUCTOR ATTRIBUTES

The constructor accepts all the following attributes that can be set in the form of attribute => 'value' pairs.

=over 4

=item B<user>

the username to login.

=item B<password>

the password used to login.

=item B<host>

the address(dns name/ip) to the ssh server

=item B<terminator>

the line terminator in use on the SSH server, this will added at the end of each command
passed to the C<exec()> method. The default is C<\r>.

=item B<verbose>

Prints on the STDOUT all the conversation between this client and the SSH server.
It also passes the option '-v' (verbose) to the wrapped ssh command, what will 
cause some ssh debugging messages to be displayed too. Useful for debugging.

=item B<timeout>

The maximum time in seconds to wait for a command to return to the PROMPT. The default is 10 seconds.
Remember to increase this attribute with the C<timeout()> method before you run a command that 
takes a long time to return.

=item B<error_handler>

TODO

=item B<cipher>

TODO

=item B<port>

alternate ssh port. default is 22.

=item B<protocol>

TODO

=item B<identity_file>

TODO

=item B<log_file>

Path to a file to save all the ssh conversation. Default is no log file.

=back

=head1 METHODS

=over 4

=item B<connect()> - establishes an ssh connection with the ssh server

=over 4

=item params:

none

=item returns:

undef

=item dies:

IllegalState: if any of 'host' or 'user' or 'password' fields are unset.

RemotePromptUnavailable: if the prompt on the remote machine can't be obtained after establishing the ssh connection

SSHProccessError: if can't spawn the ssh process

SSHConnectionError: if the connection failed for some reason, like invalid 'host' address or network problems.

=back

=item B<exec($remote_cmd [, $block])> - executes a command in the remote machine

=over 4

=item params:

$remote_cmd: a string with the command line to be run in the remote server.

$block: 0 or 1. Blocks until remote_cmd returns. Default is 0.

=over 4

0: does not block until prompt goes back, waiting util C<timeout> seconds;  

1: blocks waiting the prompt to return after running the $remote_cmd.

=back

=back

=item returns:

undef: if after running 'cmd_string' and waiting for 'timeout' seconds the prompt still didn't return. This can happen if  'cmd_string' takes a long time to conclude.

empty string: if the command sent doesn't have output.

string: a string containing all the output of the command ran. it can be a non readable character if this was the output. This can be memory intensive depending on the size of the output.

=item dies:

IllegalState: if this there is no valid ssh connection established

IllegalArgument: if no argument (no command string) is passed to this method.

RemotePromptUnavailable: if the prompt is not available for execution of $remote_cmd

=back

=item B<close()> - terminates the ssh connection

=over 4

=item returns:

undef

=back

=item B<get_expect()> - returns a connected Expect object

=over 4

=item params:

none

=item returns:

an C<Expect> object connected to the SSH server. It will die if you try to run it without being connected.

=item dies:

IllegalState: if this there is no valid ssh connection established

=back


=back
=head1 SEE ALSO

Net::SCP::Expect, Net::SCP, Net::SSH::Perl, L<Expect>

If you have a mailing list set up for your module, mention it here.

If you have a web site set up for your module, mention it here.

=head1 AUTHOR

Bruno Negrao Guimaraes Zica. E<lt>bnegrao@cpan.orgE<gt>.

=head1 THANKS

Daniel Berger, author of Net::SCP::Expect

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2007 by Bruno Negrao Guimaraes Zica

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.3 or,
at your option, any later version of Perl 5 you may have available.

=cut
