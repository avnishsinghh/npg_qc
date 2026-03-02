package npg_qc_viewer::Controller::Auth;

use Moose;
use namespace::autoclean;

BEGIN { extends 'Catalyst::Controller' }

our $VERSION = '0';

sub _get_raw_param {
    my ( $self, $c, $param_name ) = @_;

    my $query_string = $c->req->env->{QUERY_STRING} // q{};

    my %raw_params;
    for my $pair ( split /&/xsm, $query_string ) {
        my ( $key, $val ) = split /=/xsm, $pair, 2;
        $raw_params{$key} = URI::Escape::uri_unescape($val // q{});
    }

    return $raw_params{$param_name};
}

sub login : Path('/auth/login') : Args(0) {
    my ( $self, $c ) = @_;

    my $username = $c->req->header('X-OIDC-Preferred-User') // q{};

    if ($username) {
        my $redirect_to = $self->_get_raw_param($c, 'redirect_to') || '/checks';
        $c->response->redirect($redirect_to);
        return 1;
    } else {
        $c->response->status('401');
        $c->response->body('Authentication failed: no username received.');
        return 0;
    }
}

sub logout : Path('/auth/logout') : Args(0) {
    my ( $self, $c ) = @_;

    my $redirect_to = $self->_get_raw_param($c, 'redirect_to') || '/checks';
    $c->session->{post_logout_redirect} = $redirect_to;

    my $post_logout_url = 'https://'
                          . $c->req->uri->authority
                          . '/auth/post-logout';

    $c->response->redirect('/callback?logout='
                           . URI::Escape::uri_escape($post_logout_url));
    return 1;
}

sub post_logout : Path('/auth/post-logout') : Args(0) {
    my ( $self, $c ) = @_;

    my $redirect_to = $c->session->{post_logout_redirect} || '/checks';
    $c->delete_session('User logged out');

    $c->response->redirect($redirect_to);
    return 1;
}

__PACKAGE__->meta->make_immutable;
1;
