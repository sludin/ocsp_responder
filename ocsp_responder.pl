
package OCSPResponder;
use strict;
use warnings;
use Data::Dumper;
use MIME::Base64;
use File::Slurp;
use Digest::MD5 qw( md5_hex );

use HTTP::Server::Simple::CGI;
use base qw( HTTP::Server::Simple::CGI );


sub handle_request
{
  my $self = shift;
  my $cgi  = shift;

  my $method = $ENV{REQUEST_METHOD};
  my $path = $ENV{PATH_INFO};

  if ( $method eq "POST" || $method eq "GET" )
  {
    my $der;

    if ( $method eq "POST" )
    {
      $der = $cgi->param( 'POSTDATA' );
    }
    else
    {
      my ($base64) = $path =~ /\/([^\/]*)$/;
      $der = decode_base64( $base64 );
    }

    my $req_md5 = md5_hex($der);
    print STDERR $method, " ", length($der), " ", $req_md5, "\n";

    my $fh = IO::File->new( "req.der", "w" ) || die $!;
    print $fh $der;
    $fh->close();

    `openssl ocsp -reqin req.der -resp_text -rsigner certs/intermediatecert.pem -rkey certs/intermediatekey.pem -index CA/index.txt -CA certs/intermediatecert.pem -respout resp.der`;

    my $resp = read_file( "resp.der" );

    my $resp_md5 = md5_hex($resp);

    print "HTTP/1.0 200 OK\r\n";
    print "Content-type: text/plain\r\n";
    print "X-OCSP-Method: $method\r\n";
    print "X-OCSP-Req: $req_md5\r\n";
    print "X-OCSP-Resp: $resp_md5\r\n";
    print "\r\n";
    print $resp;
  }
  else
  {
    print "HTTP/1.0 405 Method Not Allowed\r\n";
  }



}

my $pid = OCSPResponder->new(8888)->run();
