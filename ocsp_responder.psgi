use strict;
use warnings;
use Data::Dumper;
use MIME::Base64;
use File::Slurp;
use Digest::MD5 qw( md5_hex );

#use HTTP::Server::Simple::CGI;
#use base qw( HTTP::Server::Simple::CGI );

my $app = sub {
  my $env = shift;

  my $method = $env->{REQUEST_METHOD};
  my $path = $env->{PATH_INFO};

  my $ret;

  if ( $method eq "POST" || $method eq "GET" )
  {
    my $der;

    if ( $method eq "POST" )
    {
      my $fh = $env->{'psgi.input'};
      while( <$fh> )
      {
        $der .= $_;
      }
    }
    else
    {
      my ($base64) = $path =~ /\/([^\/]*)$/;
      $der = decode_base64( $base64 );
    }

    my $tmp_req = "req.der";
    my $tmp_resp = "resp.der";

    my $fh = IO::File->new( $tmp_req, "w" ) || die $!;
    print $fh $der;
    $fh->close();

    my $INDEX   = "CA/index.txt";
    my $CA      = "certs/intermediatecert.pem";
    my $RSIGNER = "certs/intermediatecert.pem";
    my $RKEY    = "certs/intermediatekey.pem";

    `openssl ocsp -reqin $tmp_req -rsigner $RSIGNER -rkey $RKEY -index $INDEX -CA $CA -respout $tmp_resp`;

    my $resp = read_file( $tmp_resp );

    my $req_md5 = md5_hex($der);
    my $resp_md5 = md5_hex($resp);

    $ret = [
      '200',
      [ 'Content-Type'  => 'application/ocsp-response',
        'X-OCSP-Method' => $method,
        'X-OCSP-Req'    => $req_md5,
        'X-OCSP-Resp'   => $resp_md5 ],
      [ $resp ]
    ];
  }
  else
  {
    $ret = [
      '405',
      [ 'Content-Type' => 'text/plain' ],
      [ "" ],
    ];
  }

  return $ret;
};
