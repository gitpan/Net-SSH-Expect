use 5.008003;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME              => 'Net::SSH::Expect',
    VERSION_FROM      => 'lib/Net/SSH/Expect.pm', # finds $VERSION
    PREREQ_PM         => {}, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM  => 'lib/Net/SSH/Expect.pm', # retrieve abstract from module
       AUTHOR         => 'brunonz@br.ibm.com LV5E7T631 NegrÃÂ£o GuimarÃÂ£es Zica <brunonz@suse.de>') : ()),
);
