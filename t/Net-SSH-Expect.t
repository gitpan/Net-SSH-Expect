# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl Net-SSH-Expect.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use Test::More tests => 1;
BEGIN { use_ok('Net::SSH::Expect') };

#########################

# Insert your test code below, the Test::More module is use()ed here so read
# its man page ( perldoc Test::More ) for help writing this test script.
ok (1, "I won't test it now. make your test when you have it installed.");
