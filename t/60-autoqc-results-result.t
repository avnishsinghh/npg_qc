use strict;
use warnings;
use Test::More tests => 11;
use Test::Exception;

use_ok ('npg_qc::autoqc::results::result');
use_ok('npg_tracking::glossary::composition::factory');
use_ok('npg_tracking::glossary::composition::component::illumina');

subtest 'object creation - old style' => sub {
    plan tests => 15;

    my $r = npg_qc::autoqc::results::result->new(id_run => 2, position => 1);
    isa_ok ($r, 'npg_qc::autoqc::results::result');

    $r = npg_qc::autoqc::results::result->new(id_run => 2, position => 1);
    is($r->check_name(), q[result], 'check name');
    is($r->class_name(), q[result], 'class name');
    is($r->package_name(), q[npg_qc::autoqc::results::result], 'class name');
    is($r->tag_index, undef, 'tag index undefined');
    ok($r->has_composition, 'composition is built');
    my $c = $r->composition->get_component(0);
    is($c->id_run, 2, 'component run id');
    is($c->position, 1, 'component position');
    is($c->tag_index, undef, 'component tag index undefined');
    is($c->subset, undef, 'component subset is undefined');

    throws_ok {npg_qc::autoqc::results::result->new()}
      qr/Can only build old style results/,
      'object with an empty composition is not built';
    throws_ok {npg_qc::autoqc::results::result->new(position => 1)}
      qr/Can only build old style results/,
      'object with an empty composition is not built';
    throws_ok {npg_qc::autoqc::results::result->new(id_run => 3)}
      qr/Attribute \(position\) does not pass the type constraint/,
      'position is needed';

    $r = npg_qc::autoqc::results::result->new(id_run => 2, position => 1, tag_index => 4);
    is($r->tag_index, 4, 'tag index set');
    lives_ok {npg_qc::autoqc::results::result->new(id_run => 2, position => 1, tag_index => undef)}
       'can pass undef for tag_index in the constructor';
};

subtest 'object creation using composition' => sub {
    plan tests => 4;

    my $f = npg_tracking::glossary::composition::factory->new();
    my $c = {id_run => 3, position => 4, tag_index => 5};
    my $comp1 = npg_tracking::glossary::composition::component::illumina->new($c);
    $f->add_component($comp1);
    $c->{'position'} = 5;
    my $comp2 = npg_tracking::glossary::composition::component::illumina->new($c);
    $f->add_component($comp2);
   
    my $r = npg_qc::autoqc::results::result->new(composition => $f->create_composition());
    is ($r->composition_subset(), undef, 'composition subset is undefined');

    $f = npg_tracking::glossary::composition::factory->new();
    $f->add_component($comp1);
    $f->add_component($comp2);
    $c->{'subset'} = 'human';
    my $comp3 = npg_tracking::glossary::composition::component::illumina->new($c);
    $f->add_component($comp3);

    $r = npg_qc::autoqc::results::result->new(composition => $f->create_composition());
    throws_ok {$r->composition_subset()} qr/Multiple subsets within the composition/,
      'error for multiple subsets';

    $f = npg_tracking::glossary::composition::factory->new();
    $f->add_component($comp3);
    $c->{'id_run'} = 6;
    my $comp4 = npg_tracking::glossary::composition::component::illumina->new($c);
    $f->add_component($comp4);
    
    $r = npg_qc::autoqc::results::result->new(composition => $f->create_composition());
    is ($r->composition_subset(), 'human', 'composition subset is "human"');

    $f = npg_tracking::glossary::composition::factory->new();
    $f->add_component($comp3);
    $f->add_component($comp4);
    $c->{'subset'} = 'phix';
    $f->add_component(
      npg_tracking::glossary::composition::component::illumina->new($c)
    );

    $r = npg_qc::autoqc::results::result->new(composition => $f->create_composition());
    throws_ok {$r->composition_subset()} qr/Multiple subsets within the composition/,
      'error for multiple subsets';
};

subtest 'saving object to and loading from file' => sub {
    plan tests => 3;

    my $r = npg_qc::autoqc::results::result->new(position => 3, id_run => 2549);
    my $saved_path = q[/tmp/autoqc_check.json];
    $r->store($saved_path);
    my $json = $r->freeze();
    is ($r->_id_run_common, 2549, 'one of private attributes is set');
    unlike($json, qr/\"_[a-z]/, 'private attributes are not serialized'); 
    delete $r->{'filename_root'};
    my $saved_r = npg_qc::autoqc::results::result->load($saved_path);
    sleep 1;
    unlink $saved_path;
    
    # Use pack() method provided by MooseX::Storage framework
    # to convert objects to hash references and strip private
    # attributes from $r.
    $r = $r->pack;
    $saved_r = $saved_r->pack;
    is_deeply($r, $saved_r, 'serialization to JSON file');
};

subtest 'object comparison' => sub {
    plan tests => 13;

    my $r = npg_qc::autoqc::results::result->new(position => 3, id_run => 2549);
    throws_ok {$r->equals_byvalue({})} qr/No parameters for comparison/, 'error when an empty hash is given in equals_byvalue';
    throws_ok {$r->equals_byvalue({position => 3, unknown => 5,})}
      qr/Can't locate object method \"unknown\"/,
     'error when a hash representing an unknown attribute is used in equals_byvalue';
    ok($r->equals_byvalue({position => 3, id_run => 2549,}), 'equals_byvalue returns true');
    ok($r->equals_byvalue({position => 3, class_name => q[result],}), 'equals_byvalue returns true');
    ok($r->equals_byvalue({position => 3, check_name => q[result], tag_index => undef,}), 'equals_byvalue returns true');
    ok(!$r->equals_byvalue({position => 3, check_name => q[result], tag_index => 0,}), 'equals_byvalue returns false');
    ok(!$r->equals_byvalue({position => 3, check_name => q[result], tag_index => 1,}), 'equals_byvalue returns false');
    ok(!$r->equals_byvalue({position => 3, class_name => q[insert_size],}), 'equals_byvalue returns false');    

    $r = npg_qc::autoqc::results::result->new(position => 3, id_run => 2549, tag_index => 5);
    ok($r->equals_byvalue({position => 3, id_run => 2549, tag_index => 5, }), 'equals_byvalue returns true');
    ok($r->equals_byvalue({position => 3, class_name => q[result],}), 'equals_byvalue returns true');
    ok(!$r->equals_byvalue({position => 3, check_name => q[result], tag_index => undef,}), 'equals_byvalue returns false');
    ok(!$r->equals_byvalue({position => 3, check_name => q[result], tag_index => 0,}), 'equals_byvalue returns false');
    ok(!$r->equals_byvalue({position => 3, check_name => q[result], tag_index => 1,}), 'equals_byvalue returns false'); 
};

subtest "accessing object's attributes" => sub {
    plan tests => 2;

    my $r = npg_qc::autoqc::results::result->new(position => 3, id_run => 2549);
    $r->set_info('Aligner', 'bwa-0.55');
    $r->set_info('Check', 'npg_qc::autoqc::check::sequence_error-7766');
    is($r->get_info('Aligner'), 'bwa-0.55', 'aligner version number stored');
    is($r->get_info('Check'), 'npg_qc::autoqc::check::sequence_error-7766', 'check version number stored');
};

subtest 'igenerating and inflating rpt key' => sub {
    plan tests => 7;

    my $r = npg_qc::autoqc::results::result->new(position => 3, id_run => 2549);
    is ($r->rpt_key, q[2549:3], 'rpt key');
    $r = npg_qc::autoqc::results::result->new(position => 3, id_run => 2549, tag_index => 0);
    is ($r->rpt_key, q[2549:3:0], 'rpt key');
    $r = npg_qc::autoqc::results::result->new(position => 3, id_run => 2549, tag_index => 3);
    is ($r->rpt_key, q[2549:3:3], 'rpt key');

    throws_ok {npg_qc::autoqc::results::result->inflate_rpt_key(q[5;6])}
        qr/Both id_run and position should be defined non-zero values /,
        'error when inflating rpt key';
    is_deeply(npg_qc::autoqc::results::result->inflate_rpt_key(q[5:6]), {id_run=>5,position=>6,}, 'rpt key inflated');
    is_deeply(npg_qc::autoqc::results::result->inflate_rpt_key(q[5:6:1]), {id_run=>5,position=>6,tag_index=>1}, 'rpt key inflated');
    is_deeply(npg_qc::autoqc::results::result->inflate_rpt_key(q[5:6:0]), {id_run=>5,position=>6,tag_index=>0}, 'rpt key inflated');
};

my $factory = npg_tracking::glossary::composition::factory->new();
my $ch = {id_run => 3, position => 4, tag_index => 5};
my $comp1 = npg_tracking::glossary::composition::component::illumina->new($ch);
$factory->add_component($comp1);
$ch->{'position'} = 5;
my $comp2 = npg_tracking::glossary::composition::component::illumina->new($ch);
$factory->add_component($comp2);
my $composition = $factory->create_composition();

subtest 'result file path' => sub {
    plan tests => 4;

    my $r = npg_qc::autoqc::results::result->new(composition => $composition);
    ok($r->can('result_file_path'), 'object has result_file_path accessor');
    is($r->result_file_path, undef, 'value undefined by default');
    lives_ok { $r->result_file_path('my path') } 'can assign a value';
    is($r->result_file_path, 'my path', 'value was assigned correctly');
};

subtest 'md5 for serialized data structures' => sub {
    plan tests => 10;

    my $pname = 'npg_qc::autoqc::results::result';
    is($pname->generate_checksum4data(), undef,
        'undefined returnd for undefined input');
    is($pname->generate_checksum4data(5), undef, 
        'undefined returnd for scalar input');
    is($pname->generate_checksum4data((5,6,7)), undef,
        'undefined returnd for list input');
    is($pname->generate_checksum4data([]), undef,
        'undefined returnd for an empty array');
    is($pname->generate_checksum4data({}), undef,
        'undefined returnd for an empty hash ref');
    is($pname->generate_checksum4data({'and' => [qw/expressionA expressionB/]}),
        '2666e9d6e4db387bdedeb0a7b92c3c04', 'correct checksum for a hash');

    my $md5 = $pname->generate_checksum4data({'and' => [qw/expressionA expressionB/],
                                              'or'  => [qw/expressionA expressionC/]});
    is($pname->generate_checksum4data({'or'   => [qw/expressionA expressionC/],
                                       'and'  => [qw/expressionA expressionB/]}),
        $md5, 'checksum value does not depend on the order of keys in a hash');
    
    $md5 = 'b0c016c3e599cb65ee3e0c8458ad6abd';
    is($pname->generate_checksum4data([qw/expressionA expressionB/]),
        $md5, 'correct checksum value for an array, called as package method');

    my $r = $pname->new(composition => $composition);
    is($pname->generate_checksum4data([qw/expressionA expressionB/]),
        $md5, 'correct checksum value for an array, called as instance method');
    dies_ok { $r->generate_checksum4data($r) }
        'error when data is a reference to an object';
};

1;
